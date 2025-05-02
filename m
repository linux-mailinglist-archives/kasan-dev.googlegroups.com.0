Return-Path: <kasan-dev+bncBDCPL7WX3MKBBHM22XAAMGQEIRHW4IA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 19A12AA7C77
	for <lists+kasan-dev@lfdr.de>; Sat,  3 May 2025 00:54:23 +0200 (CEST)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-6f2c9e1f207sf47015426d6.1
        for <lists+kasan-dev@lfdr.de>; Fri, 02 May 2025 15:54:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746226462; cv=pass;
        d=google.com; s=arc-20240605;
        b=bmYDU6EV6cFNkK9E5ZpDGpNiWlbv1qtXQyAC4ToPkmE3adraLjWnDfSkBOK4I2cJ9P
         6fEQFg9IaZMeCjny77IpNKIfALK2XCLWSSusoPF9k6HFVwmGdnIJmd+DmZmQ8VrTddzW
         fuc7oddu0ZckgD3whu8/4s+i78ezLZD5OQAsKGfJ1Sn3pwZ9SO7efHwNV2JMK7got/CC
         WokLKyFV0/1ryC1pek5R+TWPXrmicDaKf+BUs2rqnhXGGPlYDbxjBUHS5K4uOgEO9Ine
         63RyZMK8+eg5MIyZEulu+k3LNbC7CNsMuMOxWgIPz6p+hEBP1+W7Ek5XzKKrP5Hc6qrK
         ntfQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=GD3avakxT87khlNGtZIsJ0mAfCHMW30+Hl9cy81rx7I=;
        fh=qOZaaVxBclJpME8Gst9r7TKBHsmr+q4WehiCz/Kdlt0=;
        b=azAmLmwvj+YBm7A4MToFfTBMp/uKKNQ28BkTiQloRn0v3yWvqn2WfjAqd0I4dqF7T9
         u3pZArqbofWyUfNM30l07c2Jkn805J626n+NpMlDEx1qNmTnPXccATAi0Cr5ZcnMazB6
         A5rFiUjLdVP9/fv+EoODYHERCm0atIr9gvzx/m9vPC7QaJJWQpSYKSMYD/AwCRKwPlZV
         ZpU/j3/hjus39GsRM/ANlEz91PcvFfXZAsPy41sEtABCd8mmGF0iEoe+QpiX9KlJ0KRZ
         UMs/wXgYtM77OEZ1A7cPKmkbXzjIVuhnGUkQoSK51Nfib2YUC4FKOKudp50J0Ddko5xu
         MjfA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=mosauOqk;
       spf=pass (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746226462; x=1746831262; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=GD3avakxT87khlNGtZIsJ0mAfCHMW30+Hl9cy81rx7I=;
        b=fl//I4EXhBxgWKEyqoOqkZ7zmGIGFeVAUE4shRCtmIlO/F3FGB5WZUaOHw67GUuVPN
         vLhH+/PE18Yamd0Ebogj5sUOMWd4dMOTYcAfNd4V+5/6Tpa/IhHo2OHo4ftIx3TsVTuh
         MwSfoJZ7GiinSjnHMhzc2PD/I1Cj2coSHev9TwXE5tBU2Mqwv853DGVj10cR7Ll3Z/LR
         my2Y0e6WpfovEbR0eCH7T8FnW1/LHW0cJc+dkb8fp+St4D+oUPzIeI8yJv7cp1XngQTm
         MceuwvQ/wNRGp7+G5e6navczTj6vK7Z2DVtl8vLDa+h07RNyT9S6VMsqXomlDNYKg0hp
         tHjg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746226462; x=1746831262;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=GD3avakxT87khlNGtZIsJ0mAfCHMW30+Hl9cy81rx7I=;
        b=VLzRpB2Ac9BQhzvGVouCChSIL+5MlkE1nm4V+uqhNOJjZdw1/yDM6A3Ppph8hKrhi1
         vVNRIlCxbZ559Rrg/GTKUkaHTqhcvmcWqS+5PXJZy27cJkuyPo3SS/ReJqbmEmntJAZL
         lUSRLBBOFv5KD0DImATm1p4V+4db0fi6oBYSwzjBDr/2mRza9SuGTIeInKM/11VuVJt9
         t0s/hvhTEKDMRg/pyPgpyHqOcpvvCV9j71DU3RHj6EqqD0PkTwXR5skUKkn5Kli75G7J
         h/uInI4MUd8DX57+VpJMWXFgdA2mf6y2VEgGsSIGZuqsP6q9/52TYjC1OdtM9YccvDlq
         zc9A==
X-Forwarded-Encrypted: i=2; AJvYcCWaN8KXUpdLUz8JVlLcO19e2j8OrZznb7krI9JCa67GLZfODv/yOPhQgxcGtUc7AqYqTmaA3g==@lfdr.de
X-Gm-Message-State: AOJu0YzCr80s6JXUlIYrpEEI3zqzEWktwphTk7wLM4w0pMwCNgOD/A1E
	sFoF757P905BEzuSFT9GvpzQ7Bvie++kAA8pjqTKUQK74aSDt7BU
X-Google-Smtp-Source: AGHT+IEQo4Y1lwQXc++PZ1bgf85OwCXcr+IISjOFU/n6QVkoOewHLa8tdifNaJAGLWsgrWYaCJzRug==
X-Received: by 2002:a05:6214:5296:b0:6e8:9e8f:cfb with SMTP id 6a1803df08f44-6f51548cb12mr71751836d6.24.1746226461791;
        Fri, 02 May 2025 15:54:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBHdPD0OH+tabSlEx70NbS/1rjjuJ805KGOtidqzLAywKg==
Received: by 2002:ad4:4b25:0:b0:6f2:bd76:f673 with SMTP id 6a1803df08f44-6f508531eabls11366646d6.2.-pod-prod-05-us;
 Fri, 02 May 2025 15:54:21 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVo1Jm2lrPZN5aqpW8YJiYJv2g3vNDit3t1JdYqtLgPsAqY/OgYXROrKzMM+rSuv7bfNd8A5NOZEyE=@googlegroups.com
X-Received: by 2002:a05:6102:9d9:b0:4da:d874:d30a with SMTP id ada2fe7eead31-4dafb4be92dmr3538679137.1.1746226460890;
        Fri, 02 May 2025 15:54:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746226460; cv=none;
        d=google.com; s=arc-20240605;
        b=AGySiFUhpEu8q41UAw2X8jeOFc1zW2vAbJojqosEp3QaaYZwptjF72eEIwdHqWQtxI
         HK7e5tghVWOwDaxwbTu6qYFskjccqruxza+sN2lUhrhnLF+t9LoiIdPAabVHRLuC5jlk
         mSYwxcFYAzCuCLhjwwHfnWqQ/FU0neocMnR/VHDY8Yt5gQhmgOUUMX5pShKCg6bsPrHi
         35WR/MJKd27Zy0FGOTKx5FC0UrXn7XjBZlWGofiv1kjpT8B8klDYf69ETRZoNkZJRN3L
         Eyss5a8U9KWWKGsXD35cuatlCCDmk9o7aw0hV4NwuZc381Yija0FRHDnwPbXfvEZvNl2
         Kx5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=ONTWqXPK16P/0zEJ7tS2nkTgsRlCDOKxvUHOtWHZvaE=;
        fh=eubRhKonGYIeWiOKI6Z2JQsuHw2wUWowqb7UcyoQPKo=;
        b=PmkkQB5bf6boxbYrtU/oGBaCnS4pdQF5qFS3WELHI50MfanGcPoWCP0bI+KEqWNkfi
         5GLDDyr7N91bjfAYxGEcBRtyiaXGeu6SQCDU3qrvagJvAuV0jZziQF7Tm8RJ1jQs0PXV
         QgWU4oqtwXR9NnexJ0uOGdlDowLpHxllgoW77h7NVvq/PwFQOllWKeCrltLHTNebGAxG
         PwLZD6AeP+fRfiy8ubBDksFkAtS/qiSs1rJ2mO8RJwug1oI9JPp2PTcQ6zow99yMyTi0
         vietFDlGLkeSYPUTirpexsIWTxBzhb/iuX1ySZ6ogrjOKfGPwEQBZAMewl3K2H//6DTK
         ZujQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=mosauOqk;
       spf=pass (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-52ae4159e08si4037e0c.4.2025.05.02.15.54.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 02 May 2025 15:54:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 0C1495C5C85;
	Fri,  2 May 2025 22:52:03 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C407DC4AF0B;
	Fri,  2 May 2025 22:54:19 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Masahiro Yamada <masahiroy@kernel.org>
Cc: Kees Cook <kees@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Petr Pavlu <petr.pavlu@suse.com>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	Justin Stitt <justinstitt@google.com>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Richard Weinberger <richard@nod.at>,
	Anton Ivanov <anton.ivanov@cambridgegreys.com>,
	Johannes Berg <johannes@sipsolutions.net>,
	linux-kernel@vger.kernel.org,
	linux-hardening@vger.kernel.org,
	linux-kbuild@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-um@lists.infradead.org
Subject: [PATCH v2 0/3] Detect changed compiler dependencies for full rebuild
Date: Fri,  2 May 2025 15:54:12 -0700
Message-Id: <20250502224512.it.706-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=2704; i=kees@kernel.org; h=from:subject:message-id; bh=WdmZa5l99Vhwe/hFJDeUIG6hQ5O76/7JBHbFIhtajXs=; b=owGbwMvMwCVmps19z/KJym7G02pJDBmivmLBof3JZfffi9rwZtw7k6/bbaezi+3JSpdr0XPDs s7wqC3uKGVhEONikBVTZAmyc49z8XjbHu4+VxFmDisTyBAGLk4BmEi1HiND56y7zgsOn5/caBvL LfxQ6GifRFBVWdwigd+l/Ac1fQtuMvx34tjpIpfatU6iObfAvlz2Uh5X7+Vuc869+hoTXMp+JLI DAA==
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=mosauOqk;       spf=pass
 (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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

 v2:
  - switch from -include to -I with a -D gated include compiler-version.h
 v1: https://lore.kernel.org/lkml/20250501193839.work.525-kees@kernel.org/

Hi,

This is my attempt to introduce dependencies that track the various
compiler behaviors that may globally change the build that aren't
represented by either compiler flags nor the compiler version
(CC_VERSION_TEXT). Namely, this is to detect when the contents of a
file the compiler uses changes. We have 3 such situations currently in
the tree:

- If any of the GCC plugins change, we need to rebuild everything that
  was built with them, as they may have changed their behavior and those
  behaviors may need to be synchronized across all translation units.
  (The most obvious of these is the randstruct GCC plugin, but is true
  for most of them.)

- If the randstruct seed itself changes (whether for GCC plugins or
  Clang), the entire tree needs to be rebuilt since the randomization of
  structures may change between compilation units if not.

- If the integer-wrap-ignore.scl file for Clang's integer wrapping
  sanitizer changes, a full rebuild is needed as the coverage for wrapping
  types may have changed, once again cause behavior differences between
  compilation units.

The best way I found to deal with this is to:
- Generate a .h file that is updated when the specific dependencies change.
  e.g.: randstruct_hash.h depends on randstruct.seed

- Add a -I argument globally to be able to locate the .h file.
  e.g.: -I$(objtree)/scripts/basic

- Add a conditional -D argument for each separate case
  e.g.: RANDSTRUCT_CFLAGS += -DRANDSTRUCT

- Include the .h file from compiler-version.h through an #ifdef for the define
  e.g.:
  #ifdef RANDSTUCT
  #include "randstruct_hash.h"
  #endif

This means that all targets gain the dependency (via fixdep), but only
when the defines are active, which means they are trivially controlled
by the existing CFLAGS removal mechanisms that are already being used
to turn off each of the above features.

-Kees

Kees Cook (3):
  gcc-plugins: Force full rebuild when plugins change
  randstruct: Force full rebuild when seed changes
  integer-wrap: Force full rebuild when .scl file changes

 Makefile                         |  1 +
 arch/um/Makefile                 |  2 ++
 include/linux/compiler-version.h | 10 ++++++++++
 include/linux/vermagic.h         |  1 -
 scripts/Makefile.gcc-plugins     |  2 +-
 scripts/Makefile.ubsan           |  1 +
 scripts/basic/Makefile           | 20 +++++++++++++++-----
 scripts/gcc-plugins/Makefile     |  8 ++++++++
 8 files changed, 38 insertions(+), 7 deletions(-)

-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250502224512.it.706-kees%40kernel.org.
