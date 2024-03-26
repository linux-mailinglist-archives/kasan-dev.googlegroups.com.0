Return-Path: <kasan-dev+bncBCP4ZTXNRIFBB2W6RSYAMGQEPHV7OLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0F32788CE77
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Mar 2024 21:26:20 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-41489c04f8csf10668895e9.3
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Mar 2024 13:26:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711484779; cv=pass;
        d=google.com; s=arc-20160816;
        b=tCSNzNbeYlsQsd/0wonXQGfWHqxzdqj7LiB8xKV+bSXHpfFaBV3rSoF5val7E9FNE6
         5sJzBFYPluFFKHUDIZE1lov6ANNsAuf8Odaj9/Cz+KV3n+0guavAvSDDroEWkU0eHoqt
         CWr++kyp/CdDFU+bXf1RgFyr3w6LD7jwY2xR9HotddDY5hN0esTjcSF7fX2o1MsHudNM
         ACLp6o3Xv9rUXUWsyJrL/hkdPLYXtzpcHWFZg9J0YfFlIbGOnW7J7ylD/8Vk0leVCebZ
         wByVxY7s+sTVAUBJt5jIkVyDhMkVcBfJFum1gQ1ukLVbhNPAefLwl1ASzFI+72WHgUci
         PB9g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=7sT/H3Wy+W4mgoJdO2hZ3WXVWtxDIcU/qBVvEkP9khA=;
        fh=JnzWmkp8UfY8lZjwjJ6L2oCWq+3uxaJlX14ru1Hh4nQ=;
        b=bGzFy2m2YUIHztiE4gB1Sb7fyJD6XiNgITpg/hhlXWH4ToPmRio6PlkcjRwnqlZCMY
         RB3JDEtU/rj2MpfOFRupgY4dwJ6e7CewZinO5YoltVrC7zys+ePzDRg07HiFGz8H9Cyn
         oQvkXSg0caR8mRNEw9BYP++O+P/lAgf9oay9B0S3fNiw6niZuk70z01M8QVxsxuPx3ph
         Pokhs6g4K5x+WjPH65LdcWTosNzKjMWF/Da90h7zDIBa2RDFCKA6PzyVer478S4ciXyP
         SrwLqcRfIvgDmc1fVGQy8RnbXH8BGEyAhXfvV7qx+O4anXo4DomDmoxUavlF/Jkmfc8m
         sxgw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=alien8 header.b=k++KNz+4;
       spf=pass (google.com: domain of bp@alien8.de designates 65.109.113.108 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711484779; x=1712089579; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=7sT/H3Wy+W4mgoJdO2hZ3WXVWtxDIcU/qBVvEkP9khA=;
        b=sQFfaF0KFwMmWUipdprbxQcn/Bqd5JgKy+KkCs/14gjwBfHqwWQ74wsdcmvoRBAQDG
         JQMi9jYF8gxPfT128MaYitoZwbqbfx7PebzU09WxXTfUYQd1K7gmFolUBxqTqCRc4AWB
         aV9H1EVz1nt0enLjAzKky5E826SMUS7/Avbh0Zy3HcK3Vrl981P9euGMnuSqompTbA8E
         AI/89F+w+idhR2+W5EUl81y6gJPd4yMbkOV9KYO+lVpgN/pyrbT69Y3koIoOemiFyEdW
         B8wQGvc5WtVqf6f9BIunr0sRrNfuqXlS+iMQL7DM1gHORj+RPX9d3HfoZxlXEy5A0yNo
         /CSw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711484779; x=1712089579;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=7sT/H3Wy+W4mgoJdO2hZ3WXVWtxDIcU/qBVvEkP9khA=;
        b=qwmYEkzNFZAzMjpnMnaQkVbSGIWJdLMkelDDmQgHZfo55ycJVMXsmxKmNNGlucT5NR
         opb+639BAIzZS0fzL93QkAfmOAR0mufV6WtZYnmCdgL+0Stz7uKF0yr1SwE42e4O5OXN
         5QXLkv6PjO4KP2voytBweD41CVfzp+R3ktM1d9e3hkiAJqPlxJwF2F2ZhckqOh5oojUD
         Uat6xl4qBCuOxkfMRUDMRoU+5/Jf8oBaljQlaTkULOuy4Jn+FtE9NCpwEpOPybH+FYzb
         4/UvA7dSPX3bLRLgyW6MixwAXP/xcc3A1aQ8FgYEG+JYcEYLYCCWf9R+qruDSvnDfsbv
         xp/g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUZAVfJLzjwDUnL0o/nxGBU9X3kjO2eV4ZBMA+AtwlHUbuuitRejOpXNJHioQ4VpIE4cJVaKvtHzbY2hPqblJflDuPX8WRS3w==
X-Gm-Message-State: AOJu0Yw3beGBWO9LnxYxL1I+kwhEo+e9qnBo8JC4CqfOP2kUr6Bzgz6B
	9tCwu1usd1099ANNX91Qh+rT73T4SzNIdrAhn9CgGD36vjEjqK77
X-Google-Smtp-Source: AGHT+IGCEVYCOZM6sC6wtlXXX/ExvjmNvgBzasRnVW38YFCdjXR44RHHNrzgMp0w0NnwLBWOyUTYIg==
X-Received: by 2002:a05:600c:3582:b0:414:8889:5a65 with SMTP id p2-20020a05600c358200b0041488895a65mr6691909wmq.30.1711484778966;
        Tue, 26 Mar 2024 13:26:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b1b:b0:414:81f3:2d6f with SMTP id
 m27-20020a05600c3b1b00b0041481f32d6fls1702997wms.0.-pod-prod-07-eu; Tue, 26
 Mar 2024 13:26:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXNvkdUonFp8A7ZukA/YTbWwB5wp181YUj1Mbpn+XVWOVh5hEhqlrU1Lm7Zi9aCupB0wAFT2p+GfBWdVTPskrO8HrDlQK0O+EklJw==
X-Received: by 2002:a05:600c:2293:b0:414:835:6ed2 with SMTP id 19-20020a05600c229300b0041408356ed2mr7858885wmf.35.1711484777020;
        Tue, 26 Mar 2024 13:26:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711484777; cv=none;
        d=google.com; s=arc-20160816;
        b=hx0GLCby65KQt0OX+ufm1jKU6zZPeOPSbBg2cQkc4Nb/4MN9v0DerbTfBS84fJrkdP
         dui0yRzKuRjm/N5qIdWaooubXu+NOh9S9tzBmsNNhfbF9tvrDmcpN7W0HIT2KT6hkUd7
         CAkAykqZpYT1muARCZ6cWcvuAVCPKyLiFO165X99kyfmvmtW2O6GKIj5Rvs+wi0eozMY
         GjtBw/6Spb+VKrBaGu7JpRHsgXwF78Ih+whwCj4x/uq8J9DNP1VISfyj6oxvmE35Temd
         oBQNbJeI1quJ3/s9mk4ag1gUDF7zP0jhJJmXVd8loniEWpuD5h23JTprkO+wxlYxNp0I
         s7oQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=3SbmZZlB5wb5VIeyhkLEZvwoIUAa+ndZFBbsOshMQUA=;
        fh=bDUrqq6yadg5U57byae1AjMk9CnRQsrx5vh7pnEbV4M=;
        b=wcQmGWD5vHE5lFBcd31pVu2flfCoe1ApRAvpM4Gos9iQ+TXv1FxA2zavL+bV2/ciA7
         g3Qb4YZ6rFief6C72HAjpxuAI5FocttIalMJlfwmDfBhlcR63/hJYyqowLB2qnlKSOry
         3njaH+WLdyu/GFxMsfZKNO2w7P370rmZ+cLYsOewDZ0OS2X76jN6gJu08vDh/NJqAftj
         sGJ9LYMo0z70R1izmGzYsIW4o0YhR5kp8l/QVDN4aYZDD7Xw/d5QzAe4BpDEubuHwB0r
         eToVCeQwm8FtgMMCfft61qro93TMA+HCNYiql5WFfQcaNc6FOqvwhzAR6QZOP3oMzQk+
         VG9w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=alien8 header.b=k++KNz+4;
       spf=pass (google.com: domain of bp@alien8.de designates 65.109.113.108 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
Received: from mail.alien8.de (mail.alien8.de. [65.109.113.108])
        by gmr-mx.google.com with ESMTPS id m14-20020a05600c3b0e00b004134299eca3si142164wms.0.2024.03.26.13.26.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 26 Mar 2024 13:26:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of bp@alien8.de designates 65.109.113.108 as permitted sender) client-ip=65.109.113.108;
Received: from localhost (localhost.localdomain [127.0.0.1])
	by mail.alien8.de (SuperMail on ZX Spectrum 128k) with ESMTP id D606540E02A2;
	Tue, 26 Mar 2024 20:26:15 +0000 (UTC)
X-Virus-Scanned: Debian amavisd-new at mail.alien8.de
Received: from mail.alien8.de ([127.0.0.1])
	by localhost (mail.alien8.de [127.0.0.1]) (amavisd-new, port 10026)
	with ESMTP id ipJStxiHWz6w; Tue, 26 Mar 2024 20:26:12 +0000 (UTC)
Received: from zn.tnic (p5de8ecf7.dip0.t-ipconnect.de [93.232.236.247])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature ECDSA (P-256) server-digest SHA256)
	(No client certificate requested)
	by mail.alien8.de (SuperMail on ZX Spectrum 128k) with ESMTPSA id 9C07A40E024C;
	Tue, 26 Mar 2024 20:25:53 +0000 (UTC)
Date: Tue, 26 Mar 2024 21:25:48 +0100
From: Borislav Petkov <bp@alien8.de>
To: Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas@fjasle.eu>, linux-kbuild@vger.kernel.org
Cc: Marco Elver <elver@google.com>, Nikolay Borisov <nik.borisov@suse.com>,
	Josh Poimboeuf <jpoimboe@kernel.org>,
	Paul Menzel <pmenzel@molgen.mpg.de>,
	Thomas Gleixner <tglx@linutronix.de>,
	Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@redhat.com>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	LKML <linux-kernel@vger.kernel.org>, kasan-dev@googlegroups.com,
	David Kaplan <David.Kaplan@amd.com>
Subject: [PATCH] kbuild: Disable KCSAN for autogenerated *.mod.c
 intermediaries
Message-ID: <20240326202548.GLZgMvTGpPfQcs2cQ_@fat_crate.local>
References: <0851a207-7143-417e-be31-8bf2b3afb57d@molgen.mpg.de>
 <47e032a0-c9a0-4639-867b-cb3d67076eaf@suse.com>
 <20240326155247.GJZgLvT_AZi3XPPpBM@fat_crate.local>
 <80582244-8c1c-4eb4-8881-db68a1428817@suse.com>
 <20240326191211.GKZgMeC21uxi7H16o_@fat_crate.local>
 <CANpmjNOcKzEvLHoGGeL-boWDHJobwfwyVxUqMq2kWeka3N4tXA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNOcKzEvLHoGGeL-boWDHJobwfwyVxUqMq2kWeka3N4tXA@mail.gmail.com>
X-Original-Sender: bp@alien8.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alien8.de header.s=alien8 header.b=k++KNz+4;       spf=pass
 (google.com: domain of bp@alien8.de designates 65.109.113.108 as permitted
 sender) smtp.mailfrom=bp@alien8.de;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=alien8.de
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

On Tue, Mar 26, 2024 at 08:33:31PM +0100, Marco Elver wrote:
> I think just removing instrumentation from the mod.c files is very reasonable.

Thanks!

@Masahiro: pls send this to Linus now as the commit which adds the
warning is in 6.9 so we should make sure we release it with all issues
fixed.

Thx.

---
From: "Borislav Petkov (AMD)" <bp@alien8.de>
Date: Tue, 26 Mar 2024 21:11:01 +0100

When KCSAN and CONSTRUCTORS are enabled, one can trigger the

  "Unpatched return thunk in use. This should not happen!"

catch-all warning.

Usually, when objtool runs on the .o objects, it does generate a section
.return_sites which contains all offsets in the objects to the return
thunks of the functions present there. Those return thunks then get
patched at runtime by the alternatives.

KCSAN and CONSTRUCTORS add this to the the object file's .text.startup
section:

  -------------------
  Disassembly of section .text.startup:

  ...

  0000000000000010 <_sub_I_00099_0>:
    10:   f3 0f 1e fa             endbr64
    14:   e8 00 00 00 00          call   19 <_sub_I_00099_0+0x9>
                          15: R_X86_64_PLT32      __tsan_init-0x4
    19:   e9 00 00 00 00          jmp    1e <__UNIQUE_ID___addressable_cryptd_alloc_aead349+0x6>
                          1a: R_X86_64_PLT32      __x86_return_thunk-0x4
  -------------------

which, if it is built as a module goes through the intermediary stage of
creating a <module>.mod.c file which, when translated, receives a second
constructor:

  -------------------
  Disassembly of section .text.startup:

  0000000000000010 <_sub_I_00099_0>:
    10:   f3 0f 1e fa             endbr64
    14:   e8 00 00 00 00          call   19 <_sub_I_00099_0+0x9>
                          15: R_X86_64_PLT32      __tsan_init-0x4
    19:   e9 00 00 00 00          jmp    1e <_sub_I_00099_0+0xe>
                          1a: R_X86_64_PLT32      __x86_return_thunk-0x4

  ...

  0000000000000030 <_sub_I_00099_0>:
    30:   f3 0f 1e fa             endbr64
    34:   e8 00 00 00 00          call   39 <_sub_I_00099_0+0x9>
                          35: R_X86_64_PLT32      __tsan_init-0x4
    39:   e9 00 00 00 00          jmp    3e <__ksymtab_cryptd_alloc_ahash+0x2>
                          3a: R_X86_64_PLT32      __x86_return_thunk-0x4
  -------------------

in the .ko file.

Objtool has run already so that second constructor's return thunk cannot
be added to the .return_sites section and thus the return thunk remains
unpatched and the warning rightfully fires.

Drop KCSAN flags from the mod.c generation stage as those constructors
do not contain data races one would be interested about.

Debugged together with David Kaplan <David.Kaplan@amd.com> and Nikolay
Borisov <nik.borisov@suse.com>.

Reported-by: Paul Menzel <pmenzel@molgen.mpg.de>
Signed-off-by: Borislav Petkov (AMD) <bp@alien8.de>
Link: https://lore.kernel.org/r/0851a207-7143-417e-be31-8bf2b3afb57d@molgen.mpg.de
---
 scripts/Makefile.modfinal | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/scripts/Makefile.modfinal b/scripts/Makefile.modfinal
index 8568d256d6fb..79fcf2731686 100644
--- a/scripts/Makefile.modfinal
+++ b/scripts/Makefile.modfinal
@@ -23,7 +23,7 @@ modname = $(notdir $(@:.mod.o=))
 part-of-module = y
 
 quiet_cmd_cc_o_c = CC [M]  $@
-      cmd_cc_o_c = $(CC) $(filter-out $(CC_FLAGS_CFI) $(CFLAGS_GCOV), $(c_flags)) -c -o $@ $<
+      cmd_cc_o_c = $(CC) $(filter-out $(CC_FLAGS_CFI) $(CFLAGS_GCOV) $(CFLAGS_KCSAN), $(c_flags)) -c -o $@ $<
 
 %.mod.o: %.mod.c FORCE
 	$(call if_changed_dep,cc_o_c)
-- 
2.43.0



-- 
Regards/Gruss,
    Boris.

https://people.kernel.org/tglx/notes-about-netiquette

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240326202548.GLZgMvTGpPfQcs2cQ_%40fat_crate.local.
