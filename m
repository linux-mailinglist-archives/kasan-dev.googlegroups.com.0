Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFX43CNQMGQECJAUBWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B4B562DD63
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Nov 2022 14:58:47 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id a20-20020a19ca14000000b004b4acd62a84sf723837lfg.23
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Nov 2022 05:58:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668693527; cv=pass;
        d=google.com; s=arc-20160816;
        b=j5lQD0z4Dldn3HA81VcxpBhm9VK+ndZYXQMPcY+x7AG0XLG0f5oiNXRwot3+6TFHYz
         hqg+cH+r7EmutSpIoKhzIGww29yyASu3Jk4Jc6apnVa5nA8T36YH8y2ewXHboqzgZUnt
         EvJhF4/sgUt9NzkOFFPKGvKwLTE08qG5ZFEjfQpMATAGakWP132/vdlSBrRK9QbFmhxC
         Q6NT2P7kRE2z6WtcDTINbr/DMe8OBhUp95RnLGVrq+o+XTEXn6Tx2YonVkCUFIk6j89u
         Yjs7iPQKOVW+xOhPKVTkJw3PWutJmJVMgNCVVilvDp9gaj6qknRxtJ062/2+ie9/DxcV
         mAog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=cDtZVVeu0sJLUQUSFXfR/+1MFsYp/3ymlnAqR0iLHuc=;
        b=uEWI7cqQCx295d/OWnPL94ARlAH7JZ/GGsVA8POaCWdqWrGXisr4T5WVybeW7ivs/R
         /NBqnO4CfajHkuBeBdLHvSXoQidVYUeHbpJo8AyS8Ewhiws5UEMLBHiEN1YujtrKi26t
         r7Os+1YFnmXEJ9l1xVyj/hlsMsoBdg0dxy/7BfTQboaHsIx7WdFVVunM5NygMLMVSq0f
         VGlUqayMEAwZ4aIE72hEWd/5vMpd6vmBggZcp8i4ptYBjmr0KE/0eDZoh4ho/SQY10uk
         qzmSYoJm8sdVHw9vp3ckzpMq+MsuCOKSAwTFzDFVXth7sb22AOHFYL8dsQXm/ajDhsLs
         5Mqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Bsf2m3Mv;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=cDtZVVeu0sJLUQUSFXfR/+1MFsYp/3ymlnAqR0iLHuc=;
        b=NdMnmVB5d8eWyqwppSDvbx3uCKiZ3/xdV8ecbycKKRghY+5gEcIoUKuep7SCwjfipU
         9EUHk5gPu+hircyu3OPZB1eq8FDXCIOB3MdUX3pCKdBYA8n5fL43T32lCaFpGBLm2x8H
         /lApmgVaGZ6ambvB1R50xrW3Mf+qENBU1m0MHbRkFMB07OuAxZH3yK5rBYVlf5F7f6MD
         bpVCgQNZ9FvVb9n98J1s4C0+RbMOTZBeZSsx9QPu1oe6nPlkVUDEMr7M2wURvSy+IVeU
         G8i/RtKaIxVVTlvOnzZlvMmnNTKr8A1yPH1VDJB+07mBQJx2tPXgejjtvuy2ZaKkBvDk
         LmLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=cDtZVVeu0sJLUQUSFXfR/+1MFsYp/3ymlnAqR0iLHuc=;
        b=6W5EVFQeu2U2uwxNtHXi2mI3nG09pAzSgkVQqaZenKW5Hg59Qpjv8cb+BQvpldB5LX
         Mkfs2SSsT+L+jFJcOi3Y7zK0mj25U/XjtojihKalYKo2CRQnOgewYBAB8qxwzxVfUnEj
         3efAE7G12N6aJwSnRKsLmubwXcWrMrskW4GiUs62k32zmG0wL8Q1LTKsdP/F7HsL1TJR
         ySLrcV2R27i0oIwJ7ffpEiCmvfJYJm/tkbFeOMEsmES/jU83NHudGx8buH1uEE8vWqBe
         FX3W+CFkyH0taWbHGOzSYDWYXxN3ck5Pt2jJgSuL699x0+PeKKKiQhjmXezRDGRwghih
         ZQHA==
X-Gm-Message-State: ANoB5pmq35HSiCOnpo9aWCnb9CkzJQWQC++mXJ++ctZbm1I4FjDC/1JU
	aB4sR1dx2LeeJse7hwwzLJs=
X-Google-Smtp-Source: AA0mqf6woXd5OjBHuHe8EWw955OgdWPlew34/YoXjSYVFCX7nH1/RBpXGEQFzDvYa8GL8U53nWIi7A==
X-Received: by 2002:a19:ca4e:0:b0:4aa:bad8:9b5d with SMTP id h14-20020a19ca4e000000b004aabad89b5dmr878937lfj.540.1668693526674;
        Thu, 17 Nov 2022 05:58:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a54a:0:b0:26e:76e9:3567 with SMTP id e10-20020a2ea54a000000b0026e76e93567ls386873ljn.11.-pod-prod-gmail;
 Thu, 17 Nov 2022 05:58:45 -0800 (PST)
X-Received: by 2002:a2e:b5cd:0:b0:26d:a666:6358 with SMTP id g13-20020a2eb5cd000000b0026da6666358mr972505ljn.148.1668693525184;
        Thu, 17 Nov 2022 05:58:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668693525; cv=none;
        d=google.com; s=arc-20160816;
        b=GAfUQAcDioROX5xjcfDYXtop4TSusEYRt0v1r54pegHoQgJ4m2QwvwCcImXXGQrE0b
         CVyvUO1zo/lN+8wxWan1MPDM/fc9YVAiLhlIHHyCincd2H/EmgYn/s4KHkim1xDJRK/h
         QF7ISvi6pqvXYqabXPVj9XUSxhquQda53KYeFnz7dxRn953/7gia8MeVrlUyVFpYgCNK
         amtf3lJ/v9gKNUhk12SfSmmlrEswpMPEy8SXCOIqiFvt9/XpUR27bi55TNliqs5lCXDh
         8H5kaNOknzfJ7SmbnT6pYFtEPkSmS7Qcgm2XEmVNSbsYZg3rJQ9ypUNjhb9R0IWKbTSd
         2F+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=1PQ5ws+dl8HGBcphz45G0mKTEEpJ4QfuhaudxhaD3+4=;
        b=lIhEx+E5yi+u6odIwgqobDV/x6wW8R0U1u8RsMGRixVXSBxryEKAR724eFD8BXuDgk
         YcldyYkTf72l9B8co1PX1dciyUtJpSvR72ess9AmksPc9RGnYi2KWiPKucGHXTieFMH3
         Csdems0WgcJSRI6Uvk8BwAwVb4E4EeqktEI9a1NhphlNgA1RrBxDbGSpAbFlZ3e1cAB1
         NJyGyfzgpPGgBU7zdR5mDW/1PfiSvBejoXw66TFDpdEOy8fk7oexQKfp6XhUsjIZ2/s4
         i4aVfv1YYlVJxmKpZRVq2awj7H8rmtLXTCA43RyaKW33mmgNEa7xmvXAKW4vbhGp9q6w
         Q87g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Bsf2m3Mv;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32f.google.com (mail-wm1-x32f.google.com. [2a00:1450:4864:20::32f])
        by gmr-mx.google.com with ESMTPS id k8-20020a2ea268000000b0027737e93a12si44436ljm.0.2022.11.17.05.58.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Nov 2022 05:58:45 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as permitted sender) client-ip=2a00:1450:4864:20::32f;
Received: by mail-wm1-x32f.google.com with SMTP id h186-20020a1c21c3000000b003cfe48519a6so5145238wmh.0
        for <kasan-dev@googlegroups.com>; Thu, 17 Nov 2022 05:58:45 -0800 (PST)
X-Received: by 2002:a05:600c:220b:b0:3cf:f747:71f with SMTP id z11-20020a05600c220b00b003cff747071fmr3728421wml.147.1668693524809;
        Thu, 17 Nov 2022 05:58:44 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:9c:201:92f0:1ec9:e9f2:5cbe])
        by smtp.gmail.com with ESMTPSA id 4-20020a05600c020400b003b492753826sm1226279wmi.43.2022.11.17.05.58.43
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Nov 2022 05:58:43 -0800 (PST)
Date: Thu, 17 Nov 2022 14:58:37 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Naresh Kamboju <naresh.kamboju@linaro.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Dave Hansen <dave.hansen@intel.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, X86 ML <x86@kernel.org>,
	open list <linux-kernel@vger.kernel.org>,
	linux-mm <linux-mm@kvack.org>, regressions@lists.linux.dev,
	lkft-triage@lists.linaro.org,
	Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>
Subject: Re: WARNING: CPU: 0 PID: 0 at arch/x86/include/asm/kfence.h:46
 kfence_protect
Message-ID: <Y3Y+DQsWa79bNuKj@elver.google.com>
References: <CA+G9fYuFxZTxkeS35VTZMXwQvohu73W3xbZ5NtjebsVvH6hCuA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CA+G9fYuFxZTxkeS35VTZMXwQvohu73W3xbZ5NtjebsVvH6hCuA@mail.gmail.com>
User-Agent: Mutt/2.2.7 (2022-08-07)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Bsf2m3Mv;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Thu, Nov 17, 2022 at 05:01PM +0530, Naresh Kamboju wrote:
> Kunit test cases failed and found warnings while booting Linux next
> version 6.1.0-rc5-next-20221117 on qemu-x86_64 [1].
> 
> It was working on Linux next-20221116 tag.
> 
> [    0.663761] WARNING: CPU: 0 PID: 0 at
> arch/x86/include/asm/kfence.h:46 kfence_protect+0x7b/0x120
> [    0.664033] WARNING: CPU: 0 PID: 0 at mm/kfence/core.c:234
> kfence_protect+0x7d/0x120
> [    0.664465] kfence: kfence_init failed
> 
> Reported-by: Linux Kernel Functional Testing <lkft@linaro.org>
[...]
> [    0.663758] ------------[ cut here ]------------
> [    0.663761] WARNING: CPU: 0 PID: 0 at
> arch/x86/include/asm/kfence.h:46 kfence_protect+0x7b/0x120
[...]
> [    0.664465] kfence: kfence_init failed
> 
> metadata:
>   git_ref: master
>   git_repo: https://gitlab.com/Linaro/lkft/mirrors/next/linux-next
>   git_sha: af37ad1e01c72483c4ee8453d9d9bac95d35f023
>   git_describe: next-20221117
>   kernel_version: 6.1.0-rc5
>   kernel-config: https://builds.tuxbuild.com/2Hfb6n1z0frt4iBlIvqUzjMHiLm/config
>   build-url: https://gitlab.com/Linaro/lkft/mirrors/next/linux-next/-/pipelines/697483979
>   artifact-location: https://builds.tuxbuild.com/2Hfb6n1z0frt4iBlIvqUzjMHiLm
>   toolchain: gcc-11

I bisected this to:

	commit 127960a05548ea699a95791669e8112552eb2452
	Author: Peter Zijlstra <peterz@infradead.org>
	Date:   Thu Nov 10 13:33:57 2022 +0100

	    x86/mm: Inhibit _PAGE_NX changes from cpa_process_alias()

	    There is a cludge in change_page_attr_set_clr() that inhibits
	    propagating NX changes to the aliases (directmap and highmap) -- this
	    is a cludge twofold:

	     - it also inhibits the primary checks in __change_page_attr();
	     - it hard depends on single bit changes.

	    The introduction of set_memory_rox() triggered this last issue for
	    clearing both _PAGE_RW and _PAGE_NX.

	    Explicitly ignore _PAGE_NX in cpa_process_alias() instead.

	    Fixes: b38994948567 ("x86/mm: Implement native set_memory_rox()")
	    Reported-by: kernel test robot <oliver.sang@intel.com>
	    Debugged-by: Dave Hansen <dave.hansen@intel.com>
	    Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
	    Link: https://lkml.kernel.org/r/20221110125544.594991716%40infradead.org

A simple revert of this commit fixes the issue.

Since all this seems to be about set_memory_rox(), and this is a fix
commit, the fix itself missed something?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y3Y%2BDQsWa79bNuKj%40elver.google.com.
