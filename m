Return-Path: <kasan-dev+bncBCAIHYNQQ4IRBGW4V6NQMGQEIELOK7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93a.google.com (mail-ua1-x93a.google.com [IPv6:2607:f8b0:4864:20::93a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5042262321C
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Nov 2022 19:14:52 +0100 (CET)
Received: by mail-ua1-x93a.google.com with SMTP id a11-20020ab0494b000000b0041123ae77cdsf8014288uad.1
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Nov 2022 10:14:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668017691; cv=pass;
        d=google.com; s=arc-20160816;
        b=xMwIECvoMSoH2H70PoyYwGG5aaq6ixp3x7X9VD3QcSfd2XJHr4S+peyuel6YYTm9Ue
         WJY5AiE7pKzwg7++TnC5PR0QVETm/sojncgoPp5O/QSBZFxnJrIupfz1cfoSKlhDRjb9
         BPIeotwmWUMbQTC2UCqf0HFuYKy69s8nJnoupyrzLGdYU6VmqiwIDDQFl1BVonEcgjFt
         ixzi1VSNf/qtUgXnRqxaJO7hZe4G5FCAV1evQU8+UhGcjXQPaWuXi9SgQIcq1b8QYq8t
         zZK+HXzdJdap4ISW8EGHfjREXbtL9xo3d46bU95rrOGO95cieQCwFdsoltQ5eTdQKfSa
         TQJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=OTbDq/pDtDIGyArdGb5vPVYjgly29M1vFqLxrP0VQ8k=;
        b=ChDqUrGVUB3jJ1B+2npCL8J1qcjIHHfSnsiDMKf8C54WxG434pNZbsxu8N01A/VV4L
         GQVeVWYnrn5PRJFDQswCl/EMzxoybQJ8g9Upff43qETVjyRiaCVjlIrEVlfPWJ0HScLM
         pH5WtPAUlPywx8skpBCNixvkeWzX4On6FsPoJBfVvXH8algQHvVzayS1fQwiIZiSQZ/K
         4Ahp+sOBoTRW2IayXFD+yVbi8rIj4Qz3mZWG9ziozq0jU8IDK/IgotV4fPCh7mfmPTjy
         BOl7+YKI/00a+X3zp4AwlTQcl/Lr92p3p2x74LiFhapQiK8fUQVgFojdJKAnEddh9/m7
         ZPAw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=KLlx0AC4;
       spf=pass (google.com: domain of seanjc@google.com designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=seanjc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=OTbDq/pDtDIGyArdGb5vPVYjgly29M1vFqLxrP0VQ8k=;
        b=rrgdD61NKfwTnbRiUdt7NpOgGdzjKW19afkIv6rQ3iz++q0c60qAJ1Qm2cMBmhIniQ
         YJ6oGajiyvvqijdhiHYP53W6baKqJ9FsBFOAVRGqYQZokatkZ5atZBeQQqadnK+QcEaO
         3pA3phv3FgOVOlb7hP0gtcJDYhUNmIg7sZLnxRCLs3o8eegVJYlni3abUfoUL3567fyz
         qfStkYy/GBEBsCQW+0UVeexXbVY865u01XIhotj2V94PYt/6l9hlUXZre4Ln1K2/aMyS
         RCgTGxpz1vbTKMtqE8cTjxjMXHXNrckHAk3XTzB7IAKeLQxSYSqQJvZ0vgIe+Bw36Nlh
         BG4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=OTbDq/pDtDIGyArdGb5vPVYjgly29M1vFqLxrP0VQ8k=;
        b=7NLCeqr/2W7XBaQ7wKSVR05iRb3EIOs1vw6U8LDbrrg9tOGvD2+JYOMJZNUjeoRJbR
         e+yAWPqqx059oBeLGnk3KaXkYygBJhC4Ksk/2zbIJcXth9lKfoUZdQQHlxdn7d8aae23
         V+XK/rPcrDwkgb8CHHRh9YkwU3E6MXYigZSSOo1dTodWcKlgMDoDhgJ1fW4SMhI3CD5a
         WTDHAaJEZXLq+gnlZY98DsnCwzG9t9BEHw0MYUjGAG8TZ3GWPPBxiitHMan/TIIcbaSC
         bm7dsuXGT4Bfm8l868pGEBdKgUus2dNr2nIbLn9lpia6AcEfjXesOgpKT4e0sI/RLRlU
         uGPg==
X-Gm-Message-State: ACrzQf29lQP3eE+/wZyjpZ2aVVQXyBQmCEwJJQ44Wr47En19yTIapbKh
	gCoP6F5OUBuFkj1sUnZZ6iI=
X-Google-Smtp-Source: AMsMyM7/8BKVU+JEC/kQnkgHGkv1/5yrgAm6Y1Rnp8QL0EomLjVrE2ERgxhHPnIPBvGUDYHQpxRmgQ==
X-Received: by 2002:a05:6102:c14:b0:3ac:6e46:f9b9 with SMTP id x20-20020a0561020c1400b003ac6e46f9b9mr30300603vss.15.1668017690988;
        Wed, 09 Nov 2022 10:14:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:e0ca:0:b0:3aa:157d:1864 with SMTP id m10-20020a67e0ca000000b003aa157d1864ls4039365vsl.11.-pod-prod-gmail;
 Wed, 09 Nov 2022 10:14:50 -0800 (PST)
X-Received: by 2002:a05:6102:3c94:b0:3a7:8ab1:244e with SMTP id c20-20020a0561023c9400b003a78ab1244emr1380440vsv.57.1668017690412;
        Wed, 09 Nov 2022 10:14:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668017690; cv=none;
        d=google.com; s=arc-20160816;
        b=lM2ae/iip+8aMWohdUO6fkMFBQeCucQ3s6Jd0FFriFrmC6gUBEhLdw7O5vbkyWwbhd
         JdCIv0YQRTidKKNsmR95V+OOpbbVh7/dfzx754dVc6/7kaNPJqMQ7t7lJLJH9TCO54yh
         lXAAmA1rvWPltoOoYP9M1ZoWKX+wkkhCkMJ6zs1Oio8Rtww5LLcipAO+g76BBaYRdI3f
         +R+JKfsfTOkTM7PH8ZJ+lqYG5dF+PIwh2u50ZA4D+Njh+Rqt8Cze+U5l9ms3MciogCoR
         kvV/vnN6Lq96O3rVWhNwNhpwWrVUZw786/NRZQ0T2b3LjI44aob+zMtG4vOHgfV9sZp8
         dJ2A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=qY9r/2KvCiduXiHY2T0U0gealLH3/TCB5NroFDjcvQE=;
        b=CDsglmR2KWy5tqpCYulmLx4M+FrXk4PObG3EmkM8I/r+XGCBY8ET10XnbGYYlmWge4
         4x/zFr5m8NRl6IapMbwkeiraa691flHJBnojpM4DRe5YSOm3gL86ccbBFehatC422AWF
         gy3JXwUhSlhiYUnNS2DtJ/cI86zlXLxprahpdsbEixMwyYevnHyLcOD4SnPiIl6VSWCe
         A5Hw1nFHnLPaB++b6KjJHs3Ss1kSXWvS5VOkQYJ93uyUFE59RpYpqNkTakxmV/J6BzA4
         JbpVqrAOoya4TDmGpIavV7aqCj7bUrLe76JMhQ5utSxDilU/ObCU1niATes9DuHDG8mA
         yHaQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=KLlx0AC4;
       spf=pass (google.com: domain of seanjc@google.com designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=seanjc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1036.google.com (mail-pj1-x1036.google.com. [2607:f8b0:4864:20::1036])
        by gmr-mx.google.com with ESMTPS id ay6-20020a056130030600b00414ee53149csi2098066uab.1.2022.11.09.10.14.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Nov 2022 10:14:50 -0800 (PST)
Received-SPF: pass (google.com: domain of seanjc@google.com designates 2607:f8b0:4864:20::1036 as permitted sender) client-ip=2607:f8b0:4864:20::1036;
Received: by mail-pj1-x1036.google.com with SMTP id c15-20020a17090a1d0f00b0021365864446so2686723pjd.4
        for <kasan-dev@googlegroups.com>; Wed, 09 Nov 2022 10:14:50 -0800 (PST)
X-Received: by 2002:a17:902:c1c6:b0:186:994f:6e57 with SMTP id c6-20020a170902c1c600b00186994f6e57mr61654253plc.17.1668017689459;
        Wed, 09 Nov 2022 10:14:49 -0800 (PST)
Received: from google.com (7.104.168.34.bc.googleusercontent.com. [34.168.104.7])
        by smtp.gmail.com with ESMTPSA id oj17-20020a17090b4d9100b00212d9a06edcsm1502645pjb.42.2022.11.09.10.14.48
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 09 Nov 2022 10:14:48 -0800 (PST)
Date: Wed, 9 Nov 2022 18:14:45 +0000
From: "'Sean Christopherson' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Dave Hansen <dave.hansen@linux.intel.com>,
	Andy Lutomirski <luto@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	x86@kernel.org, Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	"H. Peter Anvin" <hpa@zytor.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	syzbot+8cdd16fd5a6c0565e227@syzkaller.appspotmail.com
Subject: Re: [PATCH 3/3] x86/kasan: Populate shadow for shared chunk of the
 CPU entry area
Message-ID: <Y2vuFY6NOuX7moeT@google.com>
References: <20221104183247.834988-1-seanjc@google.com>
 <20221104183247.834988-4-seanjc@google.com>
 <06debc96-ea5d-df61-3d2e-0d1d723e55b7@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <06debc96-ea5d-df61-3d2e-0d1d723e55b7@gmail.com>
X-Original-Sender: seanjc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=KLlx0AC4;       spf=pass
 (google.com: domain of seanjc@google.com designates 2607:f8b0:4864:20::1036
 as permitted sender) smtp.mailfrom=seanjc@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Sean Christopherson <seanjc@google.com>
Reply-To: Sean Christopherson <seanjc@google.com>
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

On Tue, Nov 08, 2022, Andrey Ryabinin wrote:
> 
> On 11/4/22 21:32, Sean Christopherson wrote:
> > @@ -409,6 +410,15 @@ void __init kasan_init(void)
> >  		kasan_mem_to_shadow((void *)VMALLOC_END + 1),
> >  		(void *)shadow_cea_begin);
> >  
> > +	/*
> > +	 * Populate the shadow for the shared portion of the CPU entry area.
> > +	 * Shadows for the per-CPU areas are mapped on-demand, as each CPU's
> > +	 * area is randomly placed somewhere in the 512GiB range and mapping
> > +	 * the entire 512GiB range is prohibitively expensive.
> > +	 */
> > +	kasan_populate_shadow(shadow_cea_begin,
> > +			      shadow_cea_per_cpu_begin, 0);
> > +
> 
> I think we can extend the kasan_populate_early_shadow() call above up to
> shadow_cea_per_cpu_begin point, instead of this.
> populate_early_shadow() maps single RO zeroed page. No one should write to the shadow for IDT.
> KASAN only needs writable shadow for linear mapping/stacks/vmalloc/global variables.

Any objection to simply converting this to use kasan_populate_early_shadow(),
i.e. to keeping a separate "populate" call for the CPU entry area?  Purely so
that it's more obvious that a small portion of the overall CPU entry area is
mapped during init.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y2vuFY6NOuX7moeT%40google.com.
