Return-Path: <kasan-dev+bncBCP4ZTXNRIFBBNV4RSYAMGQEWWHS35I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id CBBA688CCD5
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Mar 2024 20:12:55 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-515bcad6690sf159288e87.0
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Mar 2024 12:12:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711480375; cv=pass;
        d=google.com; s=arc-20160816;
        b=nkVEyY8RBRU/+M6PHoE334R7WB3GCcNakiZfGKWPIoz/QuSyY9yq8EB5G05lK5KT6O
         nF2mxzHI2+soD3Qu0y1TLyq71aCsp/003TxAkwxv3OvH0TmUbgQB684Z+yKifmwey7Va
         vzNW0/e2ctDVbhe8/ZPmklSpbmG+TyXqpEj1FwSk/Yn97xhC9GhxStKBOeIm2arEkXc7
         e468ogGVzzUTYcalHOpNp/4l/8+tcG4MHgFzsP2dcQ6Lmyor3Xo3MBejVdf6Wc4avbDN
         OcX9eMg+Ow3+skwkgbuhse7axdiH/yd98qyzNyeLoOH85/uIV7HZZP7AmmQmra6DjZ3w
         YkvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=80Ktsig3Yq3LI/OH4sdm+33XnU/t5rYDY7TOVjzm6cM=;
        fh=cas800/EbEv8FiLw1WGAJqdShFk95LZ/61cNzEdmTsc=;
        b=CDTAlzS5FUgcWH2gCBQ2xvsP5j0U3EHlJBHIe9Bk8fBzjLE7heJzSkfULWlBe9Cj72
         a9Kdj3OfJN+uG5lQxQ/D81vif2LLx42smNDZtAHVA2K61yFtavvaxx3PetDWXAebnwnV
         /IRgo0e1bOvUqIVrgZ6OBvvdOVNXcrKIfyEZP8LH0i74533U4pvJnVDaAvJBgTjsCuNI
         h2b68jaLfmqQojyv6GeqzuwFDGQrxmzNZgfgq4Bw4J9MxQuf1XscgAtn5BVh74EVpJO0
         EDj3giFGoivhNwOE6dCy/hoi0FDbeKwGAh7QGKvXKVZUZu+csZRK7stm0EXzWdUTfntr
         MOBQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=alien8 header.b=lNXVLKDt;
       spf=pass (google.com: domain of bp@alien8.de designates 2a01:4f9:3051:3f93::2 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711480375; x=1712085175; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=80Ktsig3Yq3LI/OH4sdm+33XnU/t5rYDY7TOVjzm6cM=;
        b=o99vq2tzqv/R5PdSQ2z+KbOoHngRugOtFcgs5lbdJ6K1y1fu6lBiUnFSkstzOrxgT5
         DqqvsaqlQNO15qyWb8vvbIW0v4ilu8Pob587C0Tz937Mm3gIf3ODO3z0aS3a5Z/yzXNK
         +rrh9pibdXtIiNntFeIqvinGWVR/CJQ8sbe1U2vCor22hUE+4ZU14kwaChjLCQQgKDF6
         9xxeMZ3aXQzmAxcMrpQUkAguE0FnWOGFQsp08cI4fkZu57eIvvTQxLJdzhYP1xhITjqk
         kb5PdWdebFY8j7XF7UiIMeIpSctOdISYe0+kYQxP0DeRTzWJiHzeiT7c28kGvkQcVms4
         5gZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711480375; x=1712085175;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=80Ktsig3Yq3LI/OH4sdm+33XnU/t5rYDY7TOVjzm6cM=;
        b=s+/yUZWMGFXCMuTjMfkw4j5LopainUF+EXnhYSvmXkjaTp6fPkXT2ydCGmtv/yDdBL
         cliJWM1aHsKHCkRDiGK9r2bq4h3EQUwHriMAllVLKiGhRNc018FhreSmxA1b1EZkp6yt
         O7ejJEMvauOIzDXINaCUxXRbmqcBO/nwueK7ap4gHCJvutaeOcBF3qfYyoUiPmNK4VmS
         v6ByI2BbHCz0zjhxY/CZ5FjDGvSKRYor0CUPm/vSwQLDBBrLAqrWy9IbUBji17MDNm82
         JX2VmYlXnr1HyxR1kF41oYu7aw8JzBf3cHGRSCQ75Xt5TCRjWLGbokHABpZL/7N2Rug4
         FCfg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXR1sYyXeWk8YjOWP/QKlXXSdgqX2LmwwXb2nvIHbH+Pz8jaeBCAg+799d9F2YC2UAl7tbInXkeBBtaJTVpgI2Raf45VGaOPg==
X-Gm-Message-State: AOJu0YyMW8LGA2RMo5+jt8ezpTVDCQuMzBejzVkhUciL5RrcZ/LNLaCN
	z5aKVfK2XfkcM9AZ4BhS6FolaRY9yBFdN4ULBoAlGYsP+4QsErGE
X-Google-Smtp-Source: AGHT+IFPr+wo1DJErpvTg8cve0rTxx1MGWWtIL+agvrVpDLqYXlGRNGTsduydO2tZs9EpkzBx4hJ1Q==
X-Received: by 2002:a05:6512:528:b0:513:2c56:f5e2 with SMTP id o8-20020a056512052800b005132c56f5e2mr319624lfc.60.1711480374297;
        Tue, 26 Mar 2024 12:12:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2214:b0:515:b137:ffc4 with SMTP id
 h20-20020a056512221400b00515b137ffc4ls578011lfu.1.-pod-prod-06-eu; Tue, 26
 Mar 2024 12:12:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUl05/8rCDSHwq1X/5DRzydnBhC5IuDLXU3w23QLy6auEB7pxd1zWrCmEDAWEk3mF5N0sHmDzkDmTyMd9DxvTBjcsntbu7Rh6bp0w==
X-Received: by 2002:a19:ca0f:0:b0:515:9578:d3bb with SMTP id a15-20020a19ca0f000000b005159578d3bbmr292780lfg.69.1711480372320;
        Tue, 26 Mar 2024 12:12:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711480372; cv=none;
        d=google.com; s=arc-20160816;
        b=pD4uUo99tVTjP1uwzVw4QDCYQtnWJ2fnzbqdbmRavC8+OHmZbWDhjHUY/L12xyxod3
         WBU6ztmDvHNRSU/piG5hqzllZ6tIJV8WAAJ0yGeCXBeZxTl3ujcD0mH2XkU+AoJaFtIp
         WdFON50rnL05YYpTxNmZUqH9lwbDeQZi3Ef/QOf+44VdLCYJujkVu+f6LT0gH6VCVM35
         39J5pKXUEjxHMJN5bjd/ONMueFIU1ihpYWxIrZxGmGBTvLRwk2BLBhQf/x2ExLvb5WgZ
         84mL2GXrV4d3lGWjLSCrzKCn9BF8N5ZcqWdr7i/GVvIPKdCygQ1WcevvYU1iF0v2EFfo
         4zNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=XXsjYyRIb1HQzV+63JjLPbHzP1gIoqqZ5bMRYD4+nG0=;
        fh=Wsh94MhXOSyrOs6ROk24J4cXES984OVpkumMn6rrPFA=;
        b=SaNai/k4HMNTM86iLI4q7KDYi0In1Ag3X/8HYetdyyeT7dLkWBYmQQbo0+87YW980K
         fjnYjj+Q6upGU+mH2vXedYuDPB2ZBGDhSUJb08pKuLLFoxK26co3KYuEFUA5E2O5qwMt
         6Y4ngebS+2EfffbZ7qA6N+TL/8gcZ4N/gMvZ5eg5G/SXi46YL5Z7EMRFKBVrAkgsymf/
         r0D3Z0M/9Fei/PXc3H4lWBLUttOi3PJBN4fmDqfxGpUG9K5hWRN97tm5Y02PjmZ5odax
         tVEUMFYd0qF9Ya9/PCYygSmx9eUFMFVN+1yDG4JLwwzXqqbkGAbDIjkgdT/GbQlRg8JP
         5XDQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=alien8 header.b=lNXVLKDt;
       spf=pass (google.com: domain of bp@alien8.de designates 2a01:4f9:3051:3f93::2 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
Received: from mail.alien8.de (mail.alien8.de. [2a01:4f9:3051:3f93::2])
        by gmr-mx.google.com with ESMTPS id o22-20020a198c16000000b00513c1ff7958si458446lfd.1.2024.03.26.12.12.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 26 Mar 2024 12:12:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of bp@alien8.de designates 2a01:4f9:3051:3f93::2 as permitted sender) client-ip=2a01:4f9:3051:3f93::2;
Received: from localhost (localhost.localdomain [127.0.0.1])
	by mail.alien8.de (SuperMail on ZX Spectrum 128k) with ESMTP id 4EEA940E024C;
	Tue, 26 Mar 2024 19:12:51 +0000 (UTC)
X-Virus-Scanned: Debian amavisd-new at mail.alien8.de
Received: from mail.alien8.de ([127.0.0.1])
	by localhost (mail.alien8.de [127.0.0.1]) (amavisd-new, port 10026)
	with ESMTP id dEwE2u3E4tLL; Tue, 26 Mar 2024 19:12:47 +0000 (UTC)
Received: from zn.tnic (p5de8ecf7.dip0.t-ipconnect.de [93.232.236.247])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature ECDSA (P-256) server-digest SHA256)
	(No client certificate requested)
	by mail.alien8.de (SuperMail on ZX Spectrum 128k) with ESMTPSA id 17D9940E00B2;
	Tue, 26 Mar 2024 19:12:35 +0000 (UTC)
Date: Tue, 26 Mar 2024 20:12:29 +0100
From: Borislav Petkov <bp@alien8.de>
To: Nikolay Borisov <nik.borisov@suse.com>, Marco Elver <elver@google.com>,
	Josh Poimboeuf <jpoimboe@kernel.org>
Cc: Paul Menzel <pmenzel@molgen.mpg.de>,
	Thomas Gleixner <tglx@linutronix.de>,
	Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@redhat.com>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	LKML <linux-kernel@vger.kernel.org>, kasan-dev@googlegroups.com,
	David Kaplan <David.Kaplan@amd.com>
Subject: Re: Unpatched return thunk in use. This should not happen!
Message-ID: <20240326191211.GKZgMeC21uxi7H16o_@fat_crate.local>
References: <0851a207-7143-417e-be31-8bf2b3afb57d@molgen.mpg.de>
 <47e032a0-c9a0-4639-867b-cb3d67076eaf@suse.com>
 <20240326155247.GJZgLvT_AZi3XPPpBM@fat_crate.local>
 <80582244-8c1c-4eb4-8881-db68a1428817@suse.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <80582244-8c1c-4eb4-8881-db68a1428817@suse.com>
X-Original-Sender: bp@alien8.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alien8.de header.s=alien8 header.b=lNXVLKDt;       spf=pass
 (google.com: domain of bp@alien8.de designates 2a01:4f9:3051:3f93::2 as
 permitted sender) smtp.mailfrom=bp@alien8.de;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=alien8.de
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

On Tue, Mar 26, 2024 at 06:04:26PM +0200, Nikolay Borisov wrote:
> So this       _sub_I_00099_0 is the compiler generated ctors that is likely
> not patched. What's strange is that when adding debugging code I see that 2
> ctors are being executed and only the 2nd one fires:
> 
> [    7.635418] in do_mod_ctors
> [    7.635425] calling 0 ctor 00000000aa7a443a
> [    7.635430] called 0 ctor
> [    7.635433] calling 1 ctor 00000000fe9d0d54
> [    7.635437] ------------[ cut here ]------------
> [    7.635441] Unpatched return thunk in use. This should not happen!

... and this is just the beginning of the rabbit hole. David and I went
all the way down.

Turns out that objtool runs on the .o files and creates the
.return_sites just fine but then the module building dance creates an
intermediary *.mod.c file and when that thing is built, KCSAN would
cause the addition of *another* constructor to .text.startup in the
module.

The .o file has one:

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


while the .ko file has two:

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

Once we've figured that out, finding a fix is easy:

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

However, I'm not sure.

I wanna say that since those are constructors then we don't care about
dynamic races there so we could exclude them from KCSAN.

If not, I could disable the warning on KCSAN. I'm thinking no one would
run KCSAN in production...

A third option would be to make objtool run on .ko files. Yeah, that
would be fun for Josh. :-P

I'd look into the direction of melver for suggestions here.

Thx.

-- 
Regards/Gruss,
    Boris.

https://people.kernel.org/tglx/notes-about-netiquette

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240326191211.GKZgMeC21uxi7H16o_%40fat_crate.local.
