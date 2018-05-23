'use strict';

const fs = require('fs');
const { exec } = require('child_process');
const { Socket } = require('net');

const inquirer = require('inquirer');
const opensslCertLib = require('node-openssl-cert');
const openssl = new opensslCertLib();
const winston = require('winston');

var logger = winston.createLogger({
    level: 'info',
    format: winston.format.json(),
    transports: [
        new winston.transports.File({ filename: 'log.log' })
    ]
});

function main() {
    // Primero, pedimos qué quiere hacer el usuario
    var queryAction = [
        {
            type: "list",
            message: "¿Qué desea hacer?",
            name: "action",
            choices: [
                "Generar CSR",
                "Generar par de claves",
                "Enviar CSR",
                "Salir del programa"
            ]
        }
    ];
    console.log("\x1b[2J\x1b[0;0H");
    inquirer.prompt(queryAction).then(answers => {
        // Comprobamos qué ha realizado
        switch (answers.action) {
            case "Generar CSR":
                generateCSR().then(() => {
                    console.log("\x1b[2J\x1b[0;0HSe ha guardado con éxito el certificado.\nGracias por usar este programa");
                });
                break;
            case "Generar par de claves":
                generateKeyPair().then(() => {
                    console.log("\x1b[2J\x1b[0;0HSe ha generado con éxito el par de claves.\nGracias por usar este programa");
                });
                break;
            case "Enviar CSR":
                sendCSR().then(() => {
                    console.log("\x1b[2J\x1b[0;0HSe ha enviado con éxito el certificado.\nGracias por usar este programa");
                });
                break;
            default:
                console.log("\x1b[2J\x1b[0;0H", "Gracias por usar este programa");
                break;
        }
    });
}

function generateCSR() {
    return new Promise((result, error) => {
        var queryCSR = [
            {
                type: "input",
                name: "commonName",
                message: "FQDN del servidor"
            },
            {
                type: "input",
                name: "organization",
                message: "Nombre de la organización",
                validate: (value) => {
                    if (!/^[a-zA-Z ]{2,}$/.test(value)) {
                        return "Por favor, introduzca el nombre de la organización con 2 o más caracteres alfabéticos.";
                    }
                    return true;
                }
            },
            {
                type: "input",
                name: "organizationalUnit",
                message: "División encargada de la organización",
                validate: (value) => {
                    if (!/^[a-zA-Z0-9 ]{2,}$/.test(value)) {
                        return "Por favor, introduzca 2 o más  caracteres alfanuméricos como identificativo de la divisón.";
                    }
                    return true;
                }
            },
            {
                type: "input",
                name: "city",
                message: "Ciudad o localidad",
                validate: (value) => {
                    if (!/^[a-zA-Z ]{2,}$/.test(value)) {
                        return "Por favor, introduzca el nombre de la ciudad o localidad con 2 o más caracteres alfabéticos.";
                    }
                    return true;
                }
            },
            {
                type: "input",
                name: "state",
                message: "Estado o región",
                validate: (value) => {
                    if (!/^[a-zA-Z ]{2,}$/.test(value)) {
                        return "Por favor, introduzca el nombre del estado o región con 2 o más caracteres alfabéticos.";
                    }
                    return true;
                }
            },
            {
                type: "input",
                name: "countryCode",
                message: "Código de 2 caracteres del país (más información en https://www.ssl.com/csrs/country_codes/)",
                validate: (value) => {
                    var validCountryCodes = ["AX", "AL", "DZ", "AS", "AD", "AO", "AI", "AQ", "AG", "AR", "AM", "AW", "AU", "AT", "AZ", "BS", "BH", "BD", "BB", "BY", "BE", "BZ", "BJ", "BM", "BT", "BO", "BQ", "BA", "BW", "BV", "BR", "IO", "BN", "BG", "BF", "BI", "KH", "CM", "CA", "CV", "KY", "CF", "TD", "CL", "CN", "CX", "CC", "CO", "KM", "CG", "CD", "CK", "CR", "CI", "HR", "CW", "CY", "CZ", "DK", "DJ", "DM", "DO", "EC", "EG", "SV", "GQ", "EE", "ET", "FK", "FO", "FJ", "FI", "FR", "GF", "PF", "TF", "GA", "GM", "GE", "DE", "GH", "GI", "GR", "GL", "GD", "GP", "GU", "GT", "GG", "GW", "GY", "HT", "HM", "VA", "HN", "HK", "HU", "IS", "IN", "ID", "IE", "IM", "IL", "IT", "JM", "JP", "JE", "JO", "KZ", "KE", "KI", "KR", "KW", "KG", "LA", "LV", "LB", "LS", "LY", "LI", "LT", "LU", "MO", "MK", "MG", "MW", "MY", "MV", "ML", "MT", "MH", "MQ", "MR", "MU", "YT", "MX", "FM", "MD", "MC", "MN", "ME", "MS", "MA", "MZ", "MM", "NA", "NR", "NP", "NL", "AN", "NC", "NZ", "NI", "NE", "NG", "NU", "NF", "MP", "NO", "OM", "PK", "PW", "PS", "PA", "PG", "PY", "PE", "PH", "PN", "PL", "PT", "PR", "QA", "RE", "RO", "RU", "SH", "KN", "LC", "PM", "VC", "WS", "SM", "ST", "SA", "SN", "RS", "SC", "SG", "TL", "SK", "SI", "SB", "SO", "ZA", "GS", "ES", "LK", "SR", "SJ", "SZ", "SE", "CH", "TW", "TJ", "TZ", "TH", "TL", "TG", "TK", "TO", "TT", "TN", "TR", "TM", "TC", "TV", "UG", "UA", "AE", "GB", "US", "UM", "UY", "UZ", "VU", "VE", "VN", "VG", "VI", "WF", "EH", "YE", "ZM"];
                    if (validCountryCodes.indexOf(value) == -1) {
                        return "Por favor, introduzca un código de país correcto.";
                    }
                    return true;
                }
            },
            {
                type: "input",
                name: "email",
                message: "Dirección de correo",
                validate: (value) => {
                    if (!/^[a-zA-Z0-9]+@[a-zA-Z0-9.]+\.[a-zA-Z]{2,3}$/.test(value)) {
                        return "Por favor, introduzca una dirección de correo válida.";
                    }
                    return true;
                }
            },
            {
                type: "input",
                name: "csrPath",
                message: "Camino donde guardar la petición de certificado"
            },
            {
                type: "list",
                name: "publicKeyQuery",
                message: "¿Posee la clave pública a enviar al certificado?",
                choices: [
                    "Sí", "No"
                ]
            }
        ]
        inquirer.prompt(queryCSR).then(answers => {
            // Comprobamos la petición de la clave, en caso de no estar debemos generarla
            new Promise((accept) => {
                switch (answers.publicKeyQuery) {
                    case "Sí":
                        // Pedimos su localización
                        inquirer.prompt([{ type: "input", name: "publicKeyPath", message: "Introduzca el camino a la clave" }]).then(pathArray => {
                            var pkPath = pathArray.publicKeyPath;
                            // Procedemos a crear el certificado
                            accept(pkPath);
                        })
                        break;
                    case "No":
                        accept(generateKeyPair());
                }
            }).then(publicKeyPath => {
                fs.readFile(publicKeyPath, (err, data) => {
                    new winston.transports.File({ filename: 'combined.log' })
                    if (err) {
                        error("\x1b[31;1mSe ha producido un error al intentar acceder a la clave\x1b[0m");
                    } else {
                        var csrOptions = {
                            hash: 'sha512',
                            subject: {
                                countryName: answers.countryCode,
                                stateOrProvinceName: answers.state,
                                localityName: answers.city,
                                organizationName: answers.organization,
                                organizationalUnitName: answers.organizationalUnit,
                                commonName: answers.commonName,
                                emailAddress: answers.email
                            },
                            extensions: {
                                basicConstraints: {
                                    critical: true,
                                    CA: true,
                                    pathlen: 1
                                },
                                keyUsage: {
                                    //critical: false,
                                    usages: [
                                        'digitalSignature',
                                        'keyEncipherment'
                                    ]
                                },
                                extendedKeyUsage: {
                                    critical: true,
                                    usages: [
                                        'serverAuth',
                                        'clientAuth'
                                    ]
                                },
                                SANs: {
                                    DNS: [
                                        'localhost'
                                    ]
                                }
                            }
                        }

                        logger.log({ level: 'info', message: csrOptions });

                        openssl.importRSAPrivateKey(data, undefined, (err, key, cmd) => {
                            openssl.generateCSR(csrOptions, key, undefined, (err, csr) => {
                                if (err) {
                                    logger.log({ level: 'error', message: err });
                                    error("\x1b[31;1mSe ha producido un error al intentar guardar el certificado\x1b[0m");
                                } else {
                                    fs.writeFile(answers.csrPath, Buffer.from(csr, "utf8"), (err) => {
                                        if (err) {
                                            error("\x1b[31;1mSe ha producido un error al intentar guardar el certificado\x1b[0m")
                                        }
                                    })
                                }
                            })
                        })
                    }
                });
            });
        });
    })
}

function generateKeyPair() {
    return new Promise((result, error) => {
        var queryKeyPair = [
            {
                type: "input",
                message: "Tamaño en bits de la clave privada",
                name: "privateSize",
                validate: (value) => {
                    if (!/^[0-9]+$/.test(value)) {
                        return "El valor en bits debe ser un número";
                    }
                    return true;
                }
            },
            {
                type: "input",
                message: "¿Dónde le gustaría guardar esta clave?",
                name: "privateKeyPath",
            }
        ];
        inquirer.prompt(queryKeyPair).then((answers) => {
            openssl.generateRSAPrivateKey({
                rsa_keygen_bits: answers.privateSize
            }, (err, privateKey) => {
                if (err) {
                    error("\x1b[31;1mSe ha producido un error al intentar generar la clave privada\x1b[0m");
                } else {
                    fs.writeFile(answers.privateKeyPath, Buffer.from(privateKey, "utf8"), (err) => {
                        if (err) {
                            error("")
                        } else {
                            result(new Promise((accept) => {
                                inquirer.prompt([{
                                    type: "confirm",
                                    name: "generatePublic",
                                    message: "¿Desea generar también la clave pública?"
                                }]).then(confirmArray => {
                                    if(confirmArray.generatePublic) {
                                        inquirer.prompt([{
                                            type: "input",
                                            name: "publicKeyPath",
                                            message: "¿Dónde le gustaría guardar la clave pública?"
                                        }]).then(answer => {
                                            exec('openssl rsa -in '+ answers.privateKeyPath +' -pubout > '+ answer.publicKeyPath,
                                              (err, stdout, stderr) => {
                                                if(err) {
                                                    error("\x1b[31;1mSe ha producido un error al intentar guardar la clave pública\x1b[0m")
                                                } else {
                                                    accept(answers.privateKeyPath);
                                                }
                                            });
                                        });
                                    } else {
                                        accept(answers.privateKeyPath);
                                    }
                                });
                            }));
                        }
                    })
                }
            })
        })
    });
}

function sendCSR() {
    return new Promise((result, error) => {
        var querySave = [
            {
                type: "input",
                name: "csrPath",
                message: "Especifique el lugar del CSR."
            },
            {
                type: "input",
                name: "remoteAddress",
                message: "Dirección del servidor CA",
                default: "127.0.0.1"
            },
            {
                type: "input",
                name: "remotePort",
                message: "Puerto del servidor CA",
                default: 8290,
                validate: (value) => {
                    if(!/[0-9]{1,5}/.test(value)) {
                        return "El puerto debe ser un número comprendido entre 0 y 65535."
                    }
                    return true;
                }
            }
        ];
        inquirer.prompt(querySave).then((answers) => {
            logger.log({
                level: 'info',
                message: "Respuestas: "+answers
            })
            fs.readFile(answers.csrPath, (err, csr) => {
                if(err) {
                    error("\x1b[31;1mSe ha producido un error al intentar abrir el certificado a enviar\x1b[0m")
                } else {
                    logger.log({
                        level: 'info',
                        message: "Se ha abierto el CSR correctamente"
                    });
                    var socket = new Socket();
                    var state = 0; // 0 - Se envía el CSR, 1 - Se recibe certificado del CA, 2 - Recibido el certificado del cliente
                    socket.connect(answers.remotePort, answers.remoteAddress, (err) => {
                        if(err) {
                            error("\x1b[31;1mSe ha producido un error al intentar conectar con la CA\x1b[0m")
                        }
                        socket.write(csr);
                        state++;
                    });
                    socket.on('data', (data) => {
                        if(state == 1) {
                            var certificate = data.toString("utf8");
                            exec("echo '" + certificate + "' | openssl x509 -text -noout", (err) => {
                                if(err) {
                                    error("\x1b[31;1mSe ha producido un error al comprobar la validez del certificado de la CA\x1b[0m")
                                } else {
                                    socket.write(Buffer.from("200"));
                                    state++;
                                }
                            });
                        } else if(state == 2) {
                            var certificate = data.toString("utf8");
                            if(certificate == "500") {
                                error("\x1b[31;1mSe ha producido un error en la CA al intentar guardar el certificado\x1b[0m")
                            } else {
                                inquirer.prompt([{ type: 'input', message: "¿Dónde quiere guardar el certificado?", name: "certificatePath"}]).then((answers) => {
                                    fs.writeFile(answers.certificatePath, data, (err) => {
                                        if(err) {
                                            error("\x1b[31;1mSe ha producido un error cuando se ha intentado guardar el certificado\x1b[0m")
                                        } else {
                                            result(certificate);
                                            socket.end();
                                        }
                                    })
                                });
                            }
                        }
                    });
                    socket.on('close', (err) => {
                        if(state != 2) {
                            error("\x1b[31;1mSe ha producido un error en la transmisión con el servidor, conexión cerrada inesperadamente\x1b[0m")
                            socket.end();
                        }
                    })
                }
            });
        });
    });
}

main();