Return-Path: <kasan-dev+bncBC7OBJGL2MHBBDMGRCBQMGQENSPCG7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id DDA0734D549
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 18:40:45 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id t28sf4416918ljo.11
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 09:40:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617036045; cv=pass;
        d=google.com; s=arc-20160816;
        b=0d6Quhw4XaF9aEnOGDXUZMTBKdwJgkL7y/8nXjSHRyje0u8X8Gj2+Qohf+e9uP0zfN
         bjbc6prHIEyp2QrNSYvJPY+IJOcW1hF8nMySKRk9cFUQDePq9bja5oZdlc0dWC2iHWw2
         FDtEJSHf4BRmGTP7qHkPPRk2cDZeGMu3oqWMGT4Zp827BUOMNn0MevuqiA3lIK+hH7EW
         DcWmVV7YmbN/LXu+59+WN9OgLj+gerDRVdeNsFwx0J7eqJvNU7t1FimMDF4G79eANomF
         4P6CSpk5BXK8AYhwFlXiPXppgbT+tAc6sdZbsb3jiL66WpCPUCiJDbJA/7LYUNzFdxIy
         W7BA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=biK8Zub+MFoHqOU4Ngokl8kVcr6fLS8lRLG1eHNPQng=;
        b=P2XdwW253BpJfoDIe5AOE0JKxp+a7wIQFutEnpFTwJ1IPcO4oA8Odv+XgYJ3/rahAS
         qck2QNLtN8Y+wVaAG0tSD0rsXozhswlVQflXLipaZr2cxpjkJ0UOI0m5pnd4BynAdVUU
         D6j8x6L6e0EahHTTmS3cuHLRiMJDuc9cbGBzW4Mq2wPlFleGD2qbkpiQbB3w4taww/wi
         O59IMhZ4jeirAOfRl1hjd0AE5Yv3cTHuY6BFJf0XRcg4MdZZ7RwyNlcrZqUa/yRvaWj4
         Vc8/Fomw0AVKjJ6VDKfWD0v+qHzKC8hl+UPs2AgAW7CynYrgWwamPPDnj5KZvvFezZHt
         TW0Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nBMEVFD3;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=biK8Zub+MFoHqOU4Ngokl8kVcr6fLS8lRLG1eHNPQng=;
        b=YBZmwnuyECsgkzdhfKXRFhami2mCavzdo2Z/Jg6tUgcYPdjEXBNQ72lODmKTi6edrI
         mByUt8gZ6nS1m5e80L172HslaglNk2JsomMUe79E36J8M+/Z7HguLhkBsgIJe3c5zZ9f
         MGkOJzg5gIW7H5M7lkkAep1hj+c256yhcWiTZuVru0/rGt1+DRXitWXsFxiz6EVLMd6H
         kkU8x6BL/qsBOf3/VhcH0QyXrvxtt4ceGneZIzNSYYMOfWrPwqf8KcRS8ZAHj2ZT3LDZ
         AMT67TxBmOJCzigs18kHdMXqRgydiZWbkBENj9xHjVO8FMJRf1CBY9P5D4i7iyRkyYvr
         szpQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=biK8Zub+MFoHqOU4Ngokl8kVcr6fLS8lRLG1eHNPQng=;
        b=CNYb1la/jOWgdHopiTnQuj719S72jAATchZ1OjO7aFcdJL+azyD2hpZRaUTJZ1L5YQ
         kdJ58X9fgsBnlDdrg4+NW9xBszovqGWkBXvA1T00CStU5A1bw6SnipwiHvvzVzxJwHuS
         Rl/rrakq/VeLqsFUQO5J+ombTPHi2b5UvuQJYQZ3XxXjGtE7iZyqIsHLRVeF9w2XbfE/
         8mMjhKbTB1lkeDgz+l2LmhpmVmV6y5BP/ehpLhTDPobYE5tQzRscNNvHLCmEi+X1idTd
         XKA8hH04VIEMptcQ/ywRSWcwiWrvLLm6mTm/EJbECWQFZvGxhfIPyN98UALPPY5dKk5B
         hIYg==
X-Gm-Message-State: AOAM533oi0xozghcNUAQJKCrg3nxYdG865RDB2khTh6HWssU38KgoTrt
	2gkqNP6VHcnJyZJnPLeIiTA=
X-Google-Smtp-Source: ABdhPJzbAtRMhw+tmoa9zpc2KrjslrvW2SE2gZI1zzHpSE0iboawHsdjMjfZk84hKaB3snq9OX1FNg==
X-Received: by 2002:a05:6512:22c9:: with SMTP id g9mr17977725lfu.286.1617036045430;
        Mon, 29 Mar 2021 09:40:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:e86:: with SMTP id 128ls2930585lfo.0.gmail; Mon, 29 Mar
 2021 09:40:44 -0700 (PDT)
X-Received: by 2002:ac2:4d42:: with SMTP id 2mr17421192lfp.51.1617036044292;
        Mon, 29 Mar 2021 09:40:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617036044; cv=none;
        d=google.com; s=arc-20160816;
        b=ic2rtbsq6E8cVJZ951zgdAI32d5YTPFzSIgeUmJ0+w/fA0TqIHPUPIZZXd8xcHSjjj
         8ZLV7VKrR1h7YlX97fk+Sr/Pmb2Rj+EfnRuVUkbtZgtAzgJI0DmzjZN0OqLyttRVMh9T
         VOPSHMCXXaNdTBlTtzCV6KrDALcG+HiM9by0e+W6ujTgIQLP0Zv/AqlxToiE3xHkzzLZ
         EKoBiO7o4dAjJzQUfBRJSIAFpw/HGlAUDyn/7hl62Y0XPv1Kw5SaOmAH1B1t+OQxIkKV
         1FCV42TFvh38B/o6JTOd3BifJA+qUNpdpZdMsGupxmjzs493Jj0RyWpTW5sFkIDzEa7E
         5xyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=i3dCfNY+4sCEsAzr0CQ0LN7wBfZVpK7A0Ceu61hxU1s=;
        b=HlMRuHCYDBV5EyRk5hljg1i7Ajg4gjncwTT6MdJ7oFWCFjJpTDLQM2719MlsoGPAay
         2a2ANGG0pFHZPujeZITXCNMO8kOHuKb9XRBYZ3Tjr6LAfTDjGRH4ICLorwwBzH8TKJCh
         g3h3gQRYxIqOSDLNU54bdQZkQwSLT2fqyN5jx6pyvSUG9M5D4WxEn/fxrTWspPolITux
         u4/MIBmFC5uuLOCeEMeEdKdhBmIRhthr9zq0SCQBhVIRSu9UPVT/WZupgiDbsSoPAoJs
         SZuzeSry+kl1mMte+n2i80S0yvEz/k6GDxi5yBkAurTQ4zTKYSNEe5srOf472fPLh6TH
         15Zw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nBMEVFD3;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42b.google.com (mail-wr1-x42b.google.com. [2a00:1450:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id f21si766897ljg.6.2021.03.29.09.40.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Mar 2021 09:40:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42b as permitted sender) client-ip=2a00:1450:4864:20::42b;
Received: by mail-wr1-x42b.google.com with SMTP id x7so13508100wrw.10
        for <kasan-dev@googlegroups.com>; Mon, 29 Mar 2021 09:40:44 -0700 (PDT)
X-Received: by 2002:adf:e38a:: with SMTP id e10mr29678375wrm.37.1617036043896;
        Mon, 29 Mar 2021 09:40:43 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:755f:9d46:d671:14be])
        by smtp.gmail.com with ESMTPSA id o11sm30017453wrq.74.2021.03.29.09.40.42
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Mar 2021 09:40:43 -0700 (PDT)
Date: Mon, 29 Mar 2021 18:40:36 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: "Sarvela, Tomi P" <tomi.p.sarvela@intel.com>
Cc: "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	Andy Lutomirski <luto@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>,
	linux-kernel@vger.kernel.org
Subject: Re: I915 CI-run with kfence enabled, issues found
Message-ID: <YGIDBAboELGgMgXy@elver.google.com>
References: <d60bba0e6f354cbdbd0ae16314edeb9a@intel.com>
 <66f453a79f2541d4b05bcd933204f1c9@intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <66f453a79f2541d4b05bcd933204f1c9@intel.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=nBMEVFD3;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42b as
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

[+Cc x86 maintainers]

On Mon, Mar 29, 2021 at 11:11AM +0000, Sarvela, Tomi P wrote:
> Hello,
> 
> I'm Tomi Sarvela, maintainer and original creator of linux i915-CI:
> https://intel-gfx-ci.01.org/
> 
> I got a hint from Martin Peres about kfence functionality in kernel, and it looked
> something we'd like to enable in future CI runs so I made a trial run on DRM-Tip.
> We've had regular KASAN-enabled runs, so the expectation was that there
> wouldn't be too many new problems exposed.
> 
> On this run two issues were found, where one is clearly kernel (GUC) issue,
> but another looked a lot like kfence issue on old platforms. Affected
> were IVB, SNB and ILK, with bug signature being:
> 
> <3> [31.556004] BUG: using smp_processor_id() in preemptible [00000000] code: ...
> <4> [31.556070] caller is invalidate_user_asid+0x13/0x50
> 
> I'm not a kernel developer myself, so I can't make hard assertions
> where the issue originates. In comparison to kernel without kfence,
> it looks like the newly enabled code is the cause because the
> "BUG: KFENCE" signature is missing from the trace
> 
> Can someone take a look at the traces and verify if the kfence issue
> exists and is not related to the rest of the kernel? 
> 
> If there is an issue tracker, I can add this information there.
> 
> Example traces:
> https://intel-gfx-ci.01.org/tree/drm-tip/kfence_1/fi-ivb-3770/igt@gem_ctx_create@basic-files.html
> 
> https://intel-gfx-ci.01.org/tree/drm-tip/kfence_1/fi-snb-2520m/igt@gem_ctx_create@basic-files.html
> 
> https://intel-gfx-ci.01.org/tree/drm-tip/kfence_1/fi-ilk-650/igt@gem_exec_create@basic.html
> 
> Kfence-exposed possible GUC issue:
> https://intel-gfx-ci.01.org/tree/drm-tip/kfence_1/fi-kbl-guc/igt@kms_addfb_basic@addfb25-modifier-no-flag.html
> 
> All results can be seen at:
> https://intel-gfx-ci.01.org/tree/drm-tip/kfence_1/index.html
> 
> CI_DRM_9910 is recent DRM-Tip commit without -rc5 pulled in yet.
> kfence_1 is same commit with kfence defaults turned on:
[...]

It looks like the code path from flush_tlb_one_kernel() to
invalidate_user_asid()'s this_cpu_ptr() has several feature checks, so
probably some feature difference between systems where it triggers and
it doesn't.

As far as I'm aware, there is no restriction on where
flush_tlb_one_kernel() is called. We could of course guard it but I
think that's wrong.

Other than that, I hope the x86 maintainers know what's going on here.

Just for reference, the stack traces in the above logs start with:

| <3> [31.556004] BUG: using smp_processor_id() in preemptible [00000000] code: dmesg/1075
| <4> [31.556070] caller is invalidate_user_asid+0x13/0x50
| <4> [31.556078] CPU: 6 PID: 1075 Comm: dmesg Not tainted 5.12.0-rc4-gda4a2b1a5479-kfence_1+ #1
| <4> [31.556081] Hardware name: Hewlett-Packard HP Pro 3500 Series/2ABF, BIOS 8.11 10/24/2012
| <4> [31.556084] Call Trace:
| <4> [31.556088]  dump_stack+0x7f/0xad
| <4> [31.556097]  check_preemption_disabled+0xc8/0xd0
| <4> [31.556104]  invalidate_user_asid+0x13/0x50
| <4> [31.556109]  flush_tlb_one_kernel+0x5/0x20
| <4> [31.556113]  kfence_protect+0x56/0x80
| 	...........

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YGIDBAboELGgMgXy%40elver.google.com.
