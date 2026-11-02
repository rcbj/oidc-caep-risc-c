// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include <stddef.h>
#include <stdio.h>
#include <string.h>

int TestDefaultScopesAndAtHash(void);
int TestSignsInWithPKCE(void);
int TestRefusesACallbackThatIsNotThisSignIn(void);
int TestAcceptsACodeOnce(void);
int TestRefusesBadTokens(void);
int TestRefreshAndClientCredentials(void);
int TestPAR(void);
int TestPostAndPrivateKeyJWT(void);
int TestReadsConfigurationFileNames(void);
int TestSignalsFlag(void);
int TestVerifiesASETAgainstTheJWKS(void);
int TestReadsSubjectForms(void);
int TestPollsAndEndsOnlyTheNamedSession(void);
int TestOidcErrorIsExported(void);

int main(int argc, char **argv) {
  struct {
    const char *name;
    int (*fn)(void);
  } tests[] = {
      {"TestDefaultScopesAndAtHash", TestDefaultScopesAndAtHash},
      {"TestSignsInWithPKCE", TestSignsInWithPKCE},
      {"TestRefusesACallbackThatIsNotThisSignIn", TestRefusesACallbackThatIsNotThisSignIn},
      {"TestAcceptsACodeOnce", TestAcceptsACodeOnce},
      {"TestRefusesBadTokens", TestRefusesBadTokens},
      {"TestRefreshAndClientCredentials", TestRefreshAndClientCredentials},
      {"TestPAR", TestPAR},
      {"TestPostAndPrivateKeyJWT", TestPostAndPrivateKeyJWT},
      {"TestReadsConfigurationFileNames", TestReadsConfigurationFileNames},
      {"TestSignalsFlag", TestSignalsFlag},
      {"TestVerifiesASETAgainstTheJWKS", TestVerifiesASETAgainstTheJWKS},
      {"TestReadsSubjectForms", TestReadsSubjectForms},
      {"TestPollsAndEndsOnlyTheNamedSession", TestPollsAndEndsOnlyTheNamedSession},
      {"TestOidcErrorIsExported", TestOidcErrorIsExported},
  };
  if (argc != 2) {
    fprintf(stderr, "usage: oidc_tests <TestName>\n");
    return 2;
  }
  for (size_t i = 0; i < sizeof tests / sizeof tests[0]; i++) {
    if (strcmp(argv[1], tests[i].name) == 0) return tests[i].fn();
  }
  fprintf(stderr, "unknown test %s\n", argv[1]);
  return 2;
}
