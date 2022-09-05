Return-Path: <kasan-dev+bncBDF2F5HG7EHBBLMH3GMAMGQET5QBZZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 54E805AD929
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 20:45:03 +0200 (CEST)
Received: by mail-qt1-x840.google.com with SMTP id o22-20020ac85a56000000b0034481129ce6sf7350998qta.19
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 11:45:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662403502; cv=pass;
        d=google.com; s=arc-20160816;
        b=BYWnGCArXO12GBCqOW/Q4ltXs8dXrZovTyjKC6+w1x1aJuLLV9t7HpVcb9h8WXyb/o
         OS+grKT3wzNJAD5/I+vtFKme+gxVa5iKFCLBHFJ3sNJUnnmj/b9HlIKxJN9xJmnHi0D8
         2QaGoiS4OMspcsHnxifytE2319fX/Xe/QIahzrVdtz6rSRpqXqFgbK98ncNunh2K8njD
         10BOvWh3gOK8xC5qF2HalffWl834FCW80xeBEPXlOliWO+0JY8R2vlIRO9BcPXAhx37T
         0F2+cRg/ozXyKSB5/kJBFZPYNRVKqeL0YtgxJymUIupv0ffeJ8otZ+a1bsiGvCQPDxiJ
         akYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:references:message-id:cc:date
         :in-reply-to:from:subject:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=XzCHKuy4WB2O5xb62Nv10HqDOEbikvBiWiK6csCdW+g=;
        b=Qb+5/9KgG73/s4f+EU/y533F4PeMcafDRsUOy99VYsYOIFcriInY/sONggz31X1/ap
         7j8QtNjUI84ZFtiH2E6tNvBEkHtylWHtN702Lh2iBMcqaj6OpvM1HGvrgk44eqe4ZfMt
         EvlCNe7LAPuqQ07L/V/N9sPBXZitK/TUMbzmxBIzd8+aq/vJ1MgwIt48IFE/JhDRUQWN
         czDZGcWxW1sMwXaX23SRgAKJaiz4nxne7tshMOIlBvKi4F5a0QnVUzKbr28Fdl0nGcJ/
         badUOYpiRrlgJwvytYKkZ6ZPr86SPnBMg6ra65eMR7ycAeJTnVwdtH6Gk+hPC7Crr108
         IJQA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="piwDQu/I";
       spf=pass (google.com: domain of nadav.amit@gmail.com designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=nadav.amit@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:references:message-id:cc:date:in-reply-to:from
         :subject:mime-version:sender:from:to:cc:subject:date;
        bh=XzCHKuy4WB2O5xb62Nv10HqDOEbikvBiWiK6csCdW+g=;
        b=h/5gbBtjtg4f1zIhl0ZWK1Kqi4HAGFnzfb+F0f3l1flbBCmcspt0gexYtnme8MBoOd
         tcMSg4nuGSt6nvDmZYwtDXVqmtYdKRVpVgAkOK6O6jx+Jr0zkdZ+MEKwVC7fLFm3QVOp
         dUbz7CSAar1y9Os9whJdwN1/HIYgCCGb8icY8jF/VExsF8TABSm7TK14mIUwcqb90I15
         RnWu4a9Yx+pXfiR5IJAz22NN0mF66RoN7HFPJcxWQ1f2wRJ6NSGoxlBlEvV6ohIK12J3
         f7Gv2ilkN5Vct66eus/mrFzDfclOzUZ0HZ9DeVqXQIj/h3SmJlp6ibl6lmdRUcflmANj
         a31w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:references:message-id:cc:date:in-reply-to:from
         :subject:mime-version:from:to:cc:subject:date;
        bh=XzCHKuy4WB2O5xb62Nv10HqDOEbikvBiWiK6csCdW+g=;
        b=G+pSgJ9xqteSfPkrHGELPriLjdaD8gsj4yve0lWr8xGlKbaaevhtjpvc+dVbxZ8ttV
         +QvHIoTCjMyzbpfhmsAfNhhB542Km5Ct77lnhoVVM3g8glAJjhIgusLt6e5sKWaLlB0u
         0UBDZd98kGcYR0x4GdxSzIYbxOIteemsWTYWWMG+cJNZDcHI4a4d7r7+p9GSGNM9QrNN
         9Zu4ydRHJvekziel/SPGFVwqCbJruJFZePNQ01TP4sffFZwOx1MUBQL5EP9/uJD5dmsZ
         ONU8+O/tN0XSaPBKCbU5QSb5PPKgYgGVcJfBBUUW2x09fD66D4INzBN+HxGnEw5IF8Nh
         Sglw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:references
         :message-id:cc:date:in-reply-to:from:subject:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=XzCHKuy4WB2O5xb62Nv10HqDOEbikvBiWiK6csCdW+g=;
        b=F1PNzfuwExyGov4cZCof7g4gKCFiyNUSyZCWcITMd+oFCswEEksz1YNkT3I40IEWon
         ttU9FqAj83qPFOOczfUR6InIzB9nXggEqsxSNVGhIFDTR4QOh+UqxinRXan9oy8MB7AQ
         gHjs/En8lN/Zuuv4Rb6i9meQXz8cOdGCwS+io+yWfhA9cNVuhABeNdUGGRKIfGrAT3Da
         mffCSX8kn4IppdAjX/J/iU47RGq0zApFh+IXBsWogoqDR8ldqrNzgbHSWYNMhNPh5D6i
         MK8q9rEoF1SPG2eZWPJ0bhLUyEjTzySE6Gp+FhG32dPnYd89POOJO5AM58FNduTHf8YN
         NL8A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2lfkHetDT8xs+L3irNhq6f603c4A0jBVp49o75QtlF7zLqZsSn
	xbjHDmmYPyTMBjo8IvrfihY=
X-Google-Smtp-Source: AA6agR7jawyk8vVCuvftGlgH9dS+0X/7Vkt+BLu4bJQISfQgVhtaaR8Ujq6HEopz3t108Y8vZtxZ8g==
X-Received: by 2002:ad4:4eec:0:b0:4a5:52eb:5cbe with SMTP id dv12-20020ad44eec000000b004a552eb5cbemr5632716qvb.34.1662403502083;
        Mon, 05 Sep 2022 11:45:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:489b:b0:33b:7974:adc with SMTP id
 fc27-20020a05622a489b00b0033b79740adcls8625825qtb.2.-pod-prod-gmail; Mon, 05
 Sep 2022 11:45:01 -0700 (PDT)
X-Received: by 2002:ac8:7fc9:0:b0:344:5620:862a with SMTP id b9-20020ac87fc9000000b003445620862amr41968188qtk.397.1662403501412;
        Mon, 05 Sep 2022 11:45:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662403501; cv=none;
        d=google.com; s=arc-20160816;
        b=nKO+w6rlly+jHaQTAZJ87azwtNQapU0OeEfCZzVOgFmFndcOBBhTtUOyXhBKNu0zmX
         tgwk1RnCe7JwDPhk+ogwgIsv2JJmu5N1ns3bBOeJuc6AFsR9glJBdCMfzvSqA8UCC7lT
         aVSPhkx+gXz7dBbqel4Jy5S4980xJ53/4RRUPadj2l39zLVmBrXGamAvb8h/3jGuULDN
         hcjV0++mG1D+/16rB7JYIGSqXyxySMxEQrEQQNDC+nyPN1nIPSCEV4KJqf7FL4a0htrH
         gBfvSAsGEnMXVKO/3M0IDNLUTaUc7DsHvaES/F8qFAZ+45jZqimDJORYNC/8vy1O62Xx
         fFzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:references:message-id:content-transfer-encoding:cc:date
         :in-reply-to:from:subject:mime-version:dkim-signature;
        bh=bp7uubPhvNdLHMSt0aPBCCek7261kdyNq09tUdxS+hw=;
        b=qnxu+b1PZk0Xx4TBWG0DOz08QVWU+OSizIhRxX+2/VVz1GIuPSp/FcHx+RdoPXAQlp
         eKrSu23M3NsLT7T5haehf1SwcPZsO+L2gREr7dTV5SpHtL/ceMJKDcCUbkHclFR9Fbew
         bzN69uxqrzqmBpiwMp13BphrkpqZxybJ+1j4l0+NRKp4MULrdS6Aw7yOLbDiWdSvNL7S
         49UuyUVxQuSRcBz591Wtd7Aa2JGbu5jjzeSar5ZkU0F1xGJ73vC6ovPJ7fI+Vy0uokBd
         ya4JPskFuD0jr7uTMpJ7VL6CJxZYqGLesNGI+lcswLsWmfkfvXrhKsBobPipGzXd4Pm9
         H1nQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="piwDQu/I";
       spf=pass (google.com: domain of nadav.amit@gmail.com designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=nadav.amit@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x42b.google.com (mail-pf1-x42b.google.com. [2607:f8b0:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id ci8-20020a05622a260800b0031ecf06e367si574406qtb.1.2022.09.05.11.45.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 11:45:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of nadav.amit@gmail.com designates 2607:f8b0:4864:20::42b as permitted sender) client-ip=2607:f8b0:4864:20::42b;
Received: by mail-pf1-x42b.google.com with SMTP id w139so9223732pfc.13
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 11:45:01 -0700 (PDT)
X-Received: by 2002:a65:6cc8:0:b0:3fe:2b89:cc00 with SMTP id g8-20020a656cc8000000b003fe2b89cc00mr43555470pgw.599.1662403500241;
        Mon, 05 Sep 2022 11:45:00 -0700 (PDT)
Received: from smtpclient.apple (c-24-6-216-183.hsd1.ca.comcast.net. [24.6.216.183])
        by smtp.gmail.com with ESMTPSA id u15-20020a170903124f00b00176ba091cd3sm1910534plh.196.2022.09.05.11.44.56
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 05 Sep 2022 11:44:59 -0700 (PDT)
Content-Type: text/plain; charset="UTF-8"
Mime-Version: 1.0 (Mac OS X Mail 16.0 \(3696.120.41.1.1\))
Subject: Re: [RFC PATCH 00/30] Code tagging framework and applications
From: Nadav Amit <nadav.amit@gmail.com>
In-Reply-To: <20220831101948.f3etturccmp5ovkl@suse.de>
Date: Mon, 5 Sep 2022 11:44:55 -0700
Cc: Kent Overstreet <kent.overstreet@linux.dev>,
 Peter Zijlstra <peterz@infradead.org>,
 Suren Baghdasaryan <surenb@google.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Michal Hocko <mhocko@suse.com>,
 Vlastimil Babka <vbabka@suse.cz>,
 Johannes Weiner <hannes@cmpxchg.org>,
 roman.gushchin@linux.dev,
 dave@stgolabs.net,
 Matthew Wilcox <willy@infradead.org>,
 liam.howlett@oracle.com,
 void@manifault.com,
 juri.lelli@redhat.com,
 ldufour@linux.ibm.com,
 Peter Xu <peterx@redhat.com>,
 David Hildenbrand <david@redhat.com>,
 Jens Axboe <axboe@kernel.dk>,
 mcgrof@kernel.org,
 masahiroy@kernel.org,
 nathan@kernel.org,
 changbin.du@intel.com,
 ytcoode@gmail.com,
 vincent.guittot@linaro.org,
 dietmar.eggemann@arm.com,
 Steven Rostedt <rostedt@goodmis.org>,
 bsegall@google.com,
 bristot@redhat.com,
 vschneid@redhat.com,
 cl@linux.com,
 penberg@kernel.org,
 iamjoonsoo.kim@lge.com,
 42.hyeyoo@gmail.com,
 glider@google.com,
 Marco Elver <elver@google.com>,
 dvyukov@google.com,
 Shakeel Butt <shakeelb@google.com>,
 Muchun Song <songmuchun@bytedance.com>,
 Arnd Bergmann <arnd@arndb.de>,
 jbaron@akamai.com,
 David Rientjes <rientjes@google.com>,
 minchan@google.com,
 kaleshsingh@google.com,
 kernel-team@android.com,
 Linux MM <linux-mm@kvack.org>,
 iommu@lists.linux.dev,
 kasan-dev@googlegroups.com,
 io-uring@vger.kernel.org,
 linux-arch <linux-arch@vger.kernel.org>,
 xen-devel@lists.xenproject.org,
 linux-bcache@vger.kernel.org,
 linux-modules@vger.kernel.org,
 LKML <linux-kernel@vger.kernel.org>
Message-Id: <8EB7F2CE-2C8E-47EA-817F-6DE2D95F0A8B@gmail.com>
References: <20220830214919.53220-1-surenb@google.com>
 <Yw8P8xZ4zqu121xL@hirez.programming.kicks-ass.net>
 <20220831084230.3ti3vitrzhzsu3fs@moria.home.lan>
 <20220831101948.f3etturccmp5ovkl@suse.de>
To: Mel Gorman <mgorman@suse.de>
X-Mailer: Apple Mail (2.3696.120.41.1.1)
X-Original-Sender: nadav.amit@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b="piwDQu/I";       spf=pass
 (google.com: domain of nadav.amit@gmail.com designates 2607:f8b0:4864:20::42b
 as permitted sender) smtp.mailfrom=nadav.amit@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Aug 31, 2022, at 3:19 AM, Mel Gorman <mgorman@suse.de> wrote:

> On Wed, Aug 31, 2022 at 04:42:30AM -0400, Kent Overstreet wrote:
>> On Wed, Aug 31, 2022 at 09:38:27AM +0200, Peter Zijlstra wrote:
>>> On Tue, Aug 30, 2022 at 02:48:49PM -0700, Suren Baghdasaryan wrote:
>>>> ===========================
>>>> Code tagging framework
>>>> ===========================
>>>> Code tag is a structure identifying a specific location in the source code
>>>> which is generated at compile time and can be embedded in an application-
>>>> specific structure. Several applications of code tagging are included in
>>>> this RFC, such as memory allocation tracking, dynamic fault injection,
>>>> latency tracking and improved error code reporting.
>>>> Basically, it takes the old trick of "define a special elf section for
>>>> objects of a given type so that we can iterate over them at runtime" and
>>>> creates a proper library for it.
>>> 
>>> I might be super dense this morning, but what!? I've skimmed through the
>>> set and I don't think I get it.
>>> 
>>> What does this provide that ftrace/kprobes don't already allow?
>> 
>> You're kidding, right?
> 
> It's a valid question. From the description, it main addition that would
> be hard to do with ftrace or probes is catching where an error code is
> returned. A secondary addition would be catching all historical state and
> not just state since the tracing started.
> 
> It's also unclear *who* would enable this. It looks like it would mostly
> have value during the development stage of an embedded platform to track
> kernel memory usage on a per-application basis in an environment where it
> may be difficult to setup tracing and tracking. Would it ever be enabled
> in production? Would a distribution ever enable this? If it's enabled, any
> overhead cannot be disabled/enabled at run or boot time so anyone enabling
> this would carry the cost without never necessarily consuming the data.
> 
> It might be an ease-of-use thing. Gathering the information from traces
> is tricky and would need combining multiple different elements and that
> is development effort but not impossible.
> 
> Whatever asking for an explanation as to why equivalent functionality
> cannot not be created from ftrace/kprobe/eBPF/whatever is reasonable.

I would note that I have a solution in the making (which pretty much works)
for this matter, and does not require any kernel changes. It produces a
call stack that leads to the code that lead to syscall failure.

The way it works is by using seccomp to trap syscall failures, and then
setting ftrace function filters and kprobes on conditional branches,
indirect branch targets and function returns.

Using symbolic execution, backtracking is performed and the condition that
lead to the failure is then pin-pointed.

I hope to share the code soon.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8EB7F2CE-2C8E-47EA-817F-6DE2D95F0A8B%40gmail.com.
