Return-Path: <kasan-dev+bncBDEKVJM7XAHRBO7GULUAKGQEAPFVI2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id D79BC49DBE
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2019 11:47:39 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id 77sf2522641ljf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2019 02:47:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560851259; cv=pass;
        d=google.com; s=arc-20160816;
        b=urfpYM5SnqogF/RJTLRMVawO2+kzqwFxMei5xjA9sADSAPbTT7lVgzEaAqkfU5Puv9
         CWm05rn+Vj16DwIqgViIPmBMa+dVVNbW4TY3g1xeHGwBu1HofGKt0ZqpQZou1NJ6OeC5
         2tKSxdFkaBOIFerXjT0CeIm/iwZsICvsLiONQeiPqJ7f0fqlN4LH3tSrpq78ivU9v5yH
         xedhPRqESdpX4dssw8EwjVnsyzxjDDwr88/8ObFM9hTvGjCByl2vT3JI+9uR+C8f+NdM
         V0QTZLxVCQKYPhK+mLp7wbMmmQffHUA81/C0V6upOTenGDHO9mji4Ifsfi2FkR41LpKb
         iqRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=VOc1QqTCpZoWhcn+qNWI44h1p1oeJu6lukDjCVjpyas=;
        b=x3XagPurN+eM9OTz5lTZzBxLSluDFccuolpfYRnBQNv+3DX2F/8WfvIiUDO0wxgc+u
         l1PbMxHxdsu3pNYXplBXhGKc/AkVpd2Qx5FFB7OHRBYl1T+fEPjJ/bsSBX0G6tj+dR3n
         mF0mwCtaKkuVCMhm2EbJGG9vU0/okDr+djQZ58TlZglvJXeYJ6GJ4pKa1zv/12PuA/0y
         /YlmBn4YxdMFcC3jxJv7GS2Sr0W0Z95CfOLiSM00uMuAkHAY1V/hvVMkCIVXAtfopQDC
         NpgBzm4TL5043iaUvrWNXCiJ8VdwToqJ7UfzWdtwtKeZyMQvz9gNN50/xa5dFuLFPWjC
         rwdw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 212.227.126.135 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VOc1QqTCpZoWhcn+qNWI44h1p1oeJu6lukDjCVjpyas=;
        b=dI5hSQzKi2zuByIl9HSS4Vf25rHn7XReptQlZCHt5AZKS0Ytfi7UfEurgwaUr1Yrpt
         Umlz89KtnTv4yYKAd2mVZCPy2LR5WUvfcw0Mb5PvZbpkgNI0B/DEUd+0k+eQ1dNCRsgV
         oGzM6NY1IwlHdTLFHt1mJHz9NcwAKql4SgfSDXHaL7AkTMZ3u+TjWSEtTJd93doBt7Fk
         meApGlpYt+29SnhvPv/rlZ0pKKQBQN7DwLgkKYIJuckAtb+xN28LEzHQ78rUGrWKGxHz
         IvgaLRB3WLZ/nUFmJh0cZza/Zh3hmV8cu57Ai6ZFRsKduyLz5mxG9bnfmPSXNDoYHAPF
         RthQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=VOc1QqTCpZoWhcn+qNWI44h1p1oeJu6lukDjCVjpyas=;
        b=JYKN6dzx7BAO9ngY49rNWnTDipyH/Ujt/V+4XpyqGiKFNUcPuQNcKApA+2akR1d/xO
         8AZLafc79vwOhr7t/4tukOKbYfUS5Zr9qfYIFwV2BvooBwtk/cT9o/KihjfyeNogt2hR
         oIaVOJh5duo7ZPoJnyfKPfS3nfvDJznOAqcLEJn6ctKxGkAzzPy0xVuLCGrn38+RrwbM
         89fkSttzCY9Vs+UJpLyjBi6H7Q+t9MPh3k5llg8o7hUuetPVjuUWf6gv/9p7UZGLakW+
         2Vg0zUfpxGFZCWM9ypi8PWIjsYS9SDSDfvU0anzkcnTuxO2zKiFr2GNqbOE7mZ2kOrpd
         NjEQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVwwnCMbjsXVPyQXxXeIUmw/2rFVjB80y0LaWKuP3rh0UkK9/e1
	oRUAe6snQYUYlu7dN8+8kg0=
X-Google-Smtp-Source: APXvYqyjjtODOltYs4hvcV7pwWWgdvkXkEbR88oyZq4l2/CwGClgMtKDjcJEbrnQ3OaY29ZPIhOoZw==
X-Received: by 2002:a2e:9213:: with SMTP id k19mr7372197ljg.237.1560851259456;
        Tue, 18 Jun 2019 02:47:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5189:: with SMTP id u9ls627852lfi.0.gmail; Tue, 18 Jun
 2019 02:47:38 -0700 (PDT)
X-Received: by 2002:ac2:596c:: with SMTP id h12mr41043924lfp.101.1560851258970;
        Tue, 18 Jun 2019 02:47:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560851258; cv=none;
        d=google.com; s=arc-20160816;
        b=K9oj2YCHUOuq4Eil65V1lPRvMAQby5NARz+m9g7qiS6GkPHCRTUja5vSaE5m+TldTb
         3ms/SPUz8f4VguCN9n8gYjxg8RlMoQk5X6pJnMPUe3xa79xIwlExGR72lS9Oct5bPQ50
         fbu3QQnj7wejSxV+O5HxzIS6Ql3FLyAyGjdKYE2agJEkSWYR4WjJ6g+GGkxVXvNFOSNj
         Xr2dc38sPnRYB+7PCmuAnNTuxqPp1YMIf/F9OQXAJii3mRDYTW77z5Z/08WcdgwsGz+V
         PJkewzx8o3Sl4SOfz04Af3y/pCEOoh5aCqZsR7CTb4r1qbMEDKEcHc01+gNC2+A1llbh
         0OCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=TQQO3m3N6l0+b3sPp3z1oMliABczEQWG1VIaOqrDRHY=;
        b=sK2LVOuhsnuAH9huXHcfzlXQXBahYhYEV2/uvk7T+6nEdNZqLZk0jxwsuqWkkKlD5j
         8VKuou4XCLFYaHTNp6vbJsbDP9eovY/KH+rZNG/L2LqATdqcxHf9E9VS2B5aLQ9mxw9B
         22Y8np196833cf0LWLlgM0G2O2WK8lBI8/rCpp88whFoug2Da7XNvMV8KmpIUI/WOrXQ
         2QcuVaQYKhYopfOW83tmbnaaW/5qdO05nS/SEdi/h20R7Msm3RtWpJc6kjn/+F2M2t4x
         4BrqR58yLNswd7GTEaZIQW5r85HpWJRD659TqNYmN0hIqXzv29SG/vIQSrDBx+cCY8o4
         02UQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 212.227.126.135 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
Received: from mout.kundenserver.de (mout.kundenserver.de. [212.227.126.135])
        by gmr-mx.google.com with ESMTPS id c15si551925lfi.5.2019.06.18.02.47.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 18 Jun 2019 02:47:38 -0700 (PDT)
Received-SPF: neutral (google.com: 212.227.126.135 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) client-ip=212.227.126.135;
Received: from threadripper.lan ([149.172.19.189]) by mrelayeu.kundenserver.de
 (mreue011 [212.227.15.129]) with ESMTPA (Nemesis) id
 1MvazO-1iVYJd1CNC-00sfaV; Tue, 18 Jun 2019 11:47:35 +0200
From: Arnd Bergmann <arnd@arndb.de>
To: Kees Cook <keescook@chromium.org>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com,
	Alexander Popov <alex.popov@linux.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Ard Biesheuvel <ard.biesheuvel@linaro.org>,
	James Morris <jmorris@namei.org>,
	"Serge E. Hallyn" <serge@hallyn.com>,
	Masahiro Yamada <yamada.masahiro@socionext.com>,
	linux-security-module@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH] structleak: disable BYREF_ALL in combination with KASAN_STACK
Date: Tue, 18 Jun 2019 11:47:13 +0200
Message-Id: <20190618094731.3677294-1-arnd@arndb.de>
X-Mailer: git-send-email 2.20.0
MIME-Version: 1.0
X-Provags-ID: V03:K1:peaZfmlkgECAGz9riypsIjV4ic/JP7FXX72Osd9/Mq+xyvBdsCS
 QBR6nMT1ohGbRCit/XsDuRwE9m62UtxQb8P0hVuaqx/phcvYootks744nTD7mnuahBKuDRd
 nlFPtsir0LRT4s7DskzMEeyJxjArgwMxWUyRsgRPXJRek+d2c5rWM1qoz78m39pnj+BpCM6
 +yskDQBig2i7wcwA6yOBg==
X-Spam-Flag: NO
X-UI-Out-Filterresults: notjunk:1;V03:K0:mt0pBl9Irk8=:bYl9+u5Pgnw4rI3NpDMYHT
 i53Q/NuCg7Ndw7pN9sP3ZPFD5oeob8tWcVRjg+sNsM7RJ5b9tSeQixOT4O5MYt/D3k3OxKKFR
 CsMMgCj6iveTYDoMsmni/ibnZEv82LWgLycDF/VppP+KZDUEtaLbGUL1zO2KSr9QbWPN8aFc+
 lRLUI9FmI141/v+985lLmm3oOfEgVbmyl/+U0etuXukfVHrJ2YAISq96Nax93pejvbGmN/R6E
 gMxHU1tztk8Bz8A9z+LMq1SuiZ+fCaWyUv7cz//JBCwF0A7R3amDs1oofWWmGIhZ2woS7knzk
 s2PUnpiym4S4dWsQXv4Nm1q7zRzXDtGcHuwqhdfls7EcfffVnoBSejJk958zKoe9Usl3xWCK1
 /VC9gy9fE8Lu+nU5LxlteBelIwC5h1mcq3slnIylUnNW+FfZ01OCbNerLhuiMZrsRfuOG3j9R
 oySFqVKdqDDE77EVHlxUtZAKaY7H5C/Y74EzN7nfv/c3E2mHSdN7IZHpEbZztPDEqa72lY1Ko
 8jW/nWO+ZzsizP7A//X5ToG2yMsjuCd3Bx4XEbTmCGpgAREI2JI637qz53t4QPAkoNsjSDSKs
 GVIY8zbeF2JUvFkqt5Xx1omS8tFFZKlzcdalZOoMjwUo0ntoXLnDbOtPirWOLhizc1pqZri7Z
 ZnGvPtxhuCnVqCQk9ESm64GpMnDxt0gfXVzKqAu1fYwaMqXdZQAOAw2Jq18zIJuTgzkyl+5Vm
 qNG0l247NeNjdJmxBsYCKJm7kUZFWaEYg7MCEg==
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 212.227.126.135 is neither permitted nor denied by best guess
 record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
Content-Type: text/plain; charset="UTF-8"
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

The combination of KASAN_STACK and GCC_PLUGIN_STRUCTLEAK_BYREF_ALL
leads to much larger kernel stack usage, as seen from the warnings
about functions that now exceed the 2048 byte limit:

drivers/media/i2c/tvp5150.c:253:1: error: the frame size of 3936 bytes is larger than 2048 bytes
fs/ocfs2/dlm/dlmrecovery.c:737:1: error: the frame size of 2088 bytes is larger than 2048 bytes
fs/ocfs2/aops.c:1892:1: error: the frame size of 2088 bytes is larger than 2048 bytes
fs/ocfs2/namei.c:1677:1: error: the frame size of 2584 bytes is larger than 2048 bytes
fs/ocfs2/super.c:1186:1: error: the frame size of 2640 bytes is larger than 2048 bytes
fs/ocfs2/xattr.c:3678:1: error: the frame size of 2176 bytes is larger than 2048 bytes
net/bridge/br_netlink.c:1505:1: error: the frame size of 2448 bytes is larger than 2048 bytes
net/ieee802154/nl802154.c:548:1: error: the frame size of 2232 bytes is larger than 2048 bytes
net/wireless/nl80211.c:1726:1: error: the frame size of 2224 bytes is larger than 2048 bytes
net/wireless/nl80211.c:6472:1: error: the frame size of 2112 bytes is larger than 2048 bytes
net/wireless/nl80211.c:2357:1: error: the frame size of 4584 bytes is larger than 2048 bytes
net/wireless/nl80211.c:5108:1: error: the frame size of 2760 bytes is larger than 2048 bytes
drivers/media/tuners/r820t.c:1327:1: error: the frame size of 2816 bytes is larger than 2048 bytes

The warnings are distracting, and risking a kernel stack overflow is
generally not beneficial to performance, so it may be best to disallow
that particular combination. This can be done by turning off either
one. I picked the dependency in GCC_PLUGIN_STRUCTLEAK_BYREF_ALL, as
this option is designed to make uninitialized stack usage less harmful
when enabled on its own, but it also prevents KASAN from detecting those
cases in which it was in fact needed.

KASAN_STACK is currently implied by KASAN on gcc, but could be made a
user selectable option if we want to allow combining (non-stack) KASAN
wtih GCC_PLUGIN_STRUCTLEAK_BYREF_ALL.

Note that it woult be possible to specifically address the files that
print the warning, but presumably the overall stack usage is still
significantly higher than in other configurations, so this would not
address the full problem.

I could not test this with CONFIG_INIT_STACK_ALL, which may or may not
suffer from a similar problem.

Fixes: 81a56f6dcd20 ("gcc-plugins: structleak: Generalize to all variable types")
Signed-off-by: Arnd Bergmann <arnd@arndb.de>
---
 security/Kconfig.hardening | 5 +++++
 1 file changed, 5 insertions(+)

diff --git a/security/Kconfig.hardening b/security/Kconfig.hardening
index c6cb2d9b2905..e742d1006a4b 100644
--- a/security/Kconfig.hardening
+++ b/security/Kconfig.hardening
@@ -73,6 +73,7 @@ choice
 	config GCC_PLUGIN_STRUCTLEAK_BYREF_ALL
 		bool "zero-init anything passed by reference (very strong)"
 		depends on GCC_PLUGINS
+		depends on !(KASAN && KASAN_STACK=1)
 		select GCC_PLUGIN_STRUCTLEAK
 		help
 		  Zero-initialize any stack variables that may be passed
@@ -80,6 +81,10 @@ choice
 		  initialized. This is intended to eliminate all classes
 		  of uninitialized stack variable exploits and information
 		  exposures.
+		  As a side-effect, this keeps a lot of variables on the
+		  stack that can otherwise be optimized out, so combining
+		  this with CONFIG_KASAN_STACK can lead to a stack overflow
+		  and is disallowed.
 
 	config INIT_STACK_ALL
 		bool "0xAA-init everything on the stack (strongest)"
-- 
2.20.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190618094731.3677294-1-arnd%40arndb.de.
For more options, visit https://groups.google.com/d/optout.
