Return-Path: <kasan-dev+bncBCLL3W4IUEDRBAW5ZCRAMGQEEGLWCPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id CB4406F5545
	for <lists+kasan-dev@lfdr.de>; Wed,  3 May 2023 11:50:59 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-4efef729387sf3122202e87.2
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 02:50:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683107459; cv=pass;
        d=google.com; s=arc-20160816;
        b=wws5KqP1y5KJ69MHAdycQrPcSQa49ow1xIJvoVtcY1+yq6rCfaAPN4u+vvHk+gKoR2
         l2MffIfMPJrMYGwAOV8lrWEHAuHEuEIP7XJD+skPecaZY8b1AOZxOQVagQbjsRIpIjSb
         uOfakBBvyDCWRK7Ixsz3puphSTr3gOsWGpSU1DfTEPybK5WDqvn22rvkdHENcEBNMJjr
         TcYC+bPy+h/wbzYa8wJTWQQS2aLlGV6Wb+zfJs7KKrPR8xu1N9neGmrzyhuCcGMbTzib
         frL16G+LwMGVlMqcBUCOIgT42ojnPneroq0Bvbg9EC0xaUASGEjkPmZ6HPDzSWp2Ey7L
         GK6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=pOdQ42Cx6DqDU/edHRktK17Ir6kIUwHHwctM3pPJmj0=;
        b=hobuf/QoiSTeoaGMs7nuT27E18LbGPZQLhq1wkeAE8dXmVVLBCU3fCZ9gSbgv74XmK
         poT/xIMq39OJD2CqEi74rlxoXUaLqaLMw2ryUBfcFY/2SeXmyo++gY2R36NzhgNQT/XF
         Abbf6eQX057WewPyzc3sdmUEF82OpXeXqOI7sSyc6hg9puIW7B8iYwOh30bd0dcBsVAA
         Q9lv8XipQFd75gPeat6pJbhMUBc2VYwUZKNSaq+1ABdzVTts8erZsRLtcJ5UKvaxkkau
         To8pTHScZzfVq+6G5Z0DE/RB4bE+rMN0yUbQmB352hEN0JfDP2Hqv8nyD0HCoG/XBfWZ
         Er3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@tesarici.cz header.s=mail header.b=o4mIxsTF;
       spf=pass (google.com: domain of petr@tesarici.cz designates 77.93.223.253 as permitted sender) smtp.mailfrom=petr@tesarici.cz;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tesarici.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683107459; x=1685699459;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pOdQ42Cx6DqDU/edHRktK17Ir6kIUwHHwctM3pPJmj0=;
        b=KWszlngIpTnh5s2UP8dMU3LoOgrPMCfcOu3247BhA4I+uzUZbCfGLTawTQkS9V3wNm
         vmcjg9owgzTLA3vDQis1EPd/6airJpTLNI/aVArfsSQwwwRgm3mYEsg4/ZG+K2UygaSW
         KHXo+6oIC6WBdY9pHzxVsrAAHR5ARglDvrqnWJsEhv7BwD7gPkRTWM8ZOEcLoCFG2q7d
         931kue1Tdhh1NnvpJqm4wne544EbsIkQzIPEiju9HSKdTUI1Db//BxXXeAQ/eJZsA578
         JSLM/14fj200gkmLCYVPYy5DwVDfh+aL2866CgJ2zoNl4EgzarjBO6jC8Dbw2Z61kMRY
         ZrSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683107459; x=1685699459;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=pOdQ42Cx6DqDU/edHRktK17Ir6kIUwHHwctM3pPJmj0=;
        b=aRrs5hSRT8NtyKa1RMr+E7bHXM9LKo44sQC3J4vqV+HSWwl26FAG3Lz5pjHPN8YaHW
         IS7nvFnwvg1fKHJQ4uP+/lFL7U/MAcunfp/qkKgSqURqPyp5dzdDm5w1eC2BFjT828+g
         cKDHVNn0RM14bIXToVMIWfPaTfn77QWd3w387eRcwSdYK6qVu1sLcrwjWPl2YeUxOTa4
         NFFAa9lq31KOoatvUmpa1M8gYv34KqiMi0oAPkQKoctZlaS3qXfcZMVIfu5Rxei+0eQj
         bAfSuIabVTI0mM9FUw9QTnY6vqkhj+iMx+SL/1fgdjQ1uNQO5hk5Eyt+kw4NEDjTNHfl
         PPNg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDxBNvJV4i5tx8twSHweBAGbarMQG/6RS58cm+NeoBKlFQFAMYRj
	02x77BEfxO2JzBY+lK9RqjM=
X-Google-Smtp-Source: ACHHUZ6YHmxEZMdZ6d37Lk1oMwJViFagOwJw1gVDMTzuMxYmLprCDw6JfF/Wf8iOfJHjxfIPwkWvZQ==
X-Received: by 2002:a19:c505:0:b0:4ea:e799:59f8 with SMTP id w5-20020a19c505000000b004eae79959f8mr671124lfe.2.1683107458968;
        Wed, 03 May 2023 02:50:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b15:b0:4e8:c8b4:347a with SMTP id
 w21-20020a0565120b1500b004e8c8b4347als239973lfu.1.-pod-prod-gmail; Wed, 03
 May 2023 02:50:57 -0700 (PDT)
X-Received: by 2002:a19:f015:0:b0:4e8:47cd:b4ba with SMTP id p21-20020a19f015000000b004e847cdb4bamr771164lfc.13.1683107457522;
        Wed, 03 May 2023 02:50:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683107457; cv=none;
        d=google.com; s=arc-20160816;
        b=g1dhZeMj5XpGN9/bRIFTWUCr76PNiLRGW8f0d2fMV/IRaIMS2OLa/ktDgBHi0pltFY
         bj7CwfC6u0+NrD3sq8abZlCA1UNIvmNlEG6D4d/wWEMUrB9dxGCVfUOIitgciXVL3I2V
         e/QLSG+7uqKZ10QR0JRjP2qROVIQLY4etpTR0zXTlgq2AQVAQ8mtV4HYhMc131Fc+Rrb
         ALx+fnSm4sxTgJaeg+dKxFzwTvarHYCPNtDEv9XoLRj9hRKsb9px5XL4cqKx2cGi8A27
         TUlScrnrgnXadkRpUqwOUIjmhn0X9DEtjQx/IItkG992HxJ/CL2q9Qp5XLUDMzln4Ppu
         nJtg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=+y9ZM8+0729QZgc5RhhK9xfq3499C6ob5rHELOyu6LA=;
        b=tCP0cDxLLnKJDFGXYTxuvyIL37aJbyDnOEp/UC7E2bIrdsT/lCYAyU7QHxUrHV7YVt
         stW0oXAtyZtaI2w+0WUUkmY5DVe9K9gOHEwWbCEpyfwiUJH/APPqI7XJp36iA6MWuUEt
         mAVIlTbZXd6rmDoRRf+xc13jzODo6YPvypNRBUUlsLKAi51EEk+8l7FLPjHd5EEG3z/P
         lqZE+HbiEdyfnrrbKqWm8l6D0XFnnZdNg9g63P3JBo/QzrEvv037/jygH6MkhTWyeOKj
         bijTtS/zzL9gHaX1UN0B9maF7vz2tKqPXhetfNsMYEVHRKeM3nSFzdFOTZWRScV9sfSk
         AN8w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@tesarici.cz header.s=mail header.b=o4mIxsTF;
       spf=pass (google.com: domain of petr@tesarici.cz designates 77.93.223.253 as permitted sender) smtp.mailfrom=petr@tesarici.cz;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tesarici.cz
Received: from bee.tesarici.cz (bee.tesarici.cz. [77.93.223.253])
        by gmr-mx.google.com with ESMTPS id cf9-20020a056512280900b004dc4bb412f7si2254608lfb.12.2023.05.03.02.50.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 May 2023 02:50:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of petr@tesarici.cz designates 77.93.223.253 as permitted sender) client-ip=77.93.223.253;
Received: from meshulam.tesarici.cz (dynamic-2a00-1028-83b8-1e7a-4427-cc85-6706-c595.ipv6.o2.cz [IPv6:2a00:1028:83b8:1e7a:4427:cc85:6706:c595])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by bee.tesarici.cz (Postfix) with ESMTPSA id 4172014F40A;
	Wed,  3 May 2023 11:50:53 +0200 (CEST)
Date: Wed, 3 May 2023 11:50:51 +0200
From: Petr =?UTF-8?B?VGVzYcWZw61r?= <petr@tesarici.cz>
To: Michal Hocko <mhocko@suse.com>
Cc: Kent Overstreet <kent.overstreet@linux.dev>, Suren Baghdasaryan
 <surenb@google.com>, akpm@linux-foundation.org, vbabka@suse.cz,
 hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de,
 dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
 corbet@lwn.net, void@manifault.com, peterz@infradead.org,
 juri.lelli@redhat.com, ldufour@linux.ibm.com, catalin.marinas@arm.com,
 will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
 dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
 david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
 nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev,
 rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com,
 yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
 hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org,
 ndesaulniers@google.com, gregkh@linuxfoundation.org, ebiggers@google.com,
 ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
 rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
 vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
 iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
 elver@google.com, dvyukov@google.com, shakeelb@google.com,
 songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
 minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 iommu@lists.linux.dev, linux-arch@vger.kernel.org,
 linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
 linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
 cgroups@vger.kernel.org
Subject: Re: [PATCH 00/40] Memory allocation profiling
Message-ID: <20230503115051.30b8a97f@meshulam.tesarici.cz>
In-Reply-To: <ZFISlX+mSx4QJDK6@dhcp22.suse.cz>
References: <20230501165450.15352-1-surenb@google.com>
	<ZFIMaflxeHS3uR/A@dhcp22.suse.cz>
	<ZFIOfb6/jHwLqg6M@moria.home.lan>
	<ZFISlX+mSx4QJDK6@dhcp22.suse.cz>
X-Mailer: Claws Mail 4.1.1 (GTK 3.24.37; x86_64-suse-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: petr@tesarici.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@tesarici.cz header.s=mail header.b=o4mIxsTF;       spf=pass
 (google.com: domain of petr@tesarici.cz designates 77.93.223.253 as permitted
 sender) smtp.mailfrom=petr@tesarici.cz;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=tesarici.cz
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

On Wed, 3 May 2023 09:51:49 +0200
Michal Hocko <mhocko@suse.com> wrote:

> On Wed 03-05-23 03:34:21, Kent Overstreet wrote:
>[...]
> > We've made this as clean and simple as posssible: a single new macro
> > invocation per allocation function, no calling convention changes (that
> > would indeed have been a lot of churn!)  
> 
> That doesn't really make the concern any less relevant. I believe you
> and Suren have made a great effort to reduce the churn as much as
> possible but looking at the diffstat the code changes are clearly there
> and you have to convince the rest of the community that this maintenance
> overhead is really worth it.

I believe this is the crucial point.

I have my own concerns about the use of preprocessor macros, which goes
against the basic idea of a code tagging framework (patch 13/40).
AFAICS the CODE_TAG_INIT macro must be expanded on the same source code
line as the tagged code, which makes it hard to use without further
macros (unless you want to make the source code unreadable beyond
imagination). That's why all allocation functions must be converted to
macros.

If anyone ever wants to use this code tagging framework for something
else, they will also have to convert relevant functions to macros,
slowly changing the kernel to a minefield where local identifiers,
struct, union and enum tags, field names and labels must avoid name
conflict with a tagged function. For now, I have to remember that
alloc_pages is forbidden, but the list may grow.

FWIW I can see some occurences of "alloc_pages" under arch/ which are
not renamed by patch 19/40 of this series. For instance, does the
kernel build for s390x after applying the patch series?

New code may also work initially, but explode after adding an #include
later...

HOWEVER, if the rest of the community agrees that the added value of
code tagging is worth all these potential risks, I can live with it.

Petr T

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230503115051.30b8a97f%40meshulam.tesarici.cz.
