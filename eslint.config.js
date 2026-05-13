import { defineConfig } from "eslint/config";
import globals from "globals";
import js from "@eslint/js";

export default defineConfig([
    {
        extends: [js.configs.recommended],
        languageOptions: {
            globals: {
                ...globals.node,
            },

            ecmaVersion: "latest",
            sourceType: "module",
        },
        rules: {
            "no-unused-vars": ["error", {
                "args": "all",
                "varsIgnorePattern": "^_",
                "argsIgnorePattern": "^_", // ignore `(t) => {...}` in ./test/ , and user|req|res
                "caughtErrorsIgnorePattern": "^_",
                "destructuredArrayIgnorePattern": "^_",
            }],
        },
    }
]);