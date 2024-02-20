Return-Path: <kasan-dev+bncBCS2NBWRUIFBBPWE2OXAMGQEQPFJJRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 37DEA85C2B5
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Feb 2024 18:32:47 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-411ffacbafdsf4075e9.1
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Feb 2024 09:32:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708450366; cv=pass;
        d=google.com; s=arc-20160816;
        b=tVEj2O/3U9ohwwem3WknO0qE8nApX+xWbRAdm8q9plW2wcoDBdx2JNU8KIj8xLjliO
         PeTQwGYaHG43MS9LPyp+Pu55Dl0/0OzVYkjwYghfi7SnHry8ctzTXUDhJkfBzLsyx/U/
         dM4MQJHg6VEVIiTlMx8RK5P3teOqIuX+ugNXR0nwP9A5y6RGkzS2PYfiM0IunBeu+YB4
         syOteAsiYLo6mg7Yh1eHjpcRPzmDVRFVhWa02CCIPuI1595LLM4zDNgfo3IgdAjpCLFL
         LTBDFpRANaNgg10MapFIdA4eNEaVxFfSqghEVqwVtZgl+OGKLAMiA7YGtoiaGRL3HF2X
         01cQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=xbtzs9SKRxHiIzZNcnLkW/89Afd56bfn81TjUlHIvZw=;
        fh=YwjdiOz8h3qh1MvI/FXAYLY/wjxR72r8LHlQjf3Wyzc=;
        b=dLw1nN9rNVTwCUfU88FMctlHpMm9YffHfZs8d0EFMd8QqnLQnmU2J4kgjtOtzZyVt/
         wA//1JrdEa7k7pWu4R+Bpv60Ee6IX8d+LowiRP+e6XH+lew8L8pRqNGdS0Et7FzkezI1
         oZkkAfrZeZEgG8zA1Jw/Y06+KU4k+QHGU5sCUqEfLtzgIzMcS8j+11xQ10cqBdXCvdtZ
         8kJCQnV55CnVIv4N7XstZPnPTI5hypdYOt432n5KHgbgnPTFM9flRDJPDkLPGMkl4JX0
         onEMX3v0xUhrm5Z10nm9mTMnqM4a69wtmmrR2mf6/S2tbAIaIWWtxwYFZ/LTLvuCp8IX
         GxGg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=fxyuYm2K;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.187 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708450366; x=1709055166; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=xbtzs9SKRxHiIzZNcnLkW/89Afd56bfn81TjUlHIvZw=;
        b=Q0YTuGJS0ZUiitSLkyBuV0QRk8Kcc1atUB9U1PAALe4dbB06F5tlZw6qY2KrP08+I8
         T80mbppHYryyoPDhbey4CQ1sOjt4W0RNcVUbuuHIs5p5sH7chk5hrD5KXyI0FkJuqzpi
         lABgCiAxaj4YBcHWx12VWkrf7WxeNSI2xW3agOiFZJg8Pex5rOX/FH8rbkI79nFmifzL
         Piw8zbvALB2ADwTHDq7GEfRtZYUUS2Mq9kf32C2bn4i7788aB5p2UqAFg9HeApHcFo7D
         RwZmEEwPp4sWmGl0UvQDUf2ZKLhtVyZmjwQ5JzYNrZY0JJS+Jl7Ghibql2KrdQ/9tuvH
         HpiQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708450366; x=1709055166;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=xbtzs9SKRxHiIzZNcnLkW/89Afd56bfn81TjUlHIvZw=;
        b=GnnT5achD0TR0Ilaz7XSS48bLnquskqPcm0eda0m0JB7vZhUICC6UIaP+3wxU6k7yA
         cp8UHpHvCbY8IsJIEidRUnMZRpcdxGrYVJlihMXgjbjBMvSyfDwNlhroc5OILGqPLXpd
         xA6epqz2xRtg9f/4XcW0aR4Pi4dg0ZhsFbj6jE539XqOUpwnHBYJvmU3mD+lRphylDej
         jiTw3PtPc9SpnxGCd59mRN2stnISKQA2gYxp41A37AVte/boANrze114Fw0HsYG5Ccxm
         E9IyBZoB/Mur9D2lU6utEBsrKI/yO4gu5DrLP+mEGZbV4+IBLOSttRNMlR/8hTGUGndX
         gftA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUcDFBb5wt0L2F/baArQOBAWzDnl0PX6E6kiqDQihVX0oJ9o1rQ7cJg6ZVqsK9H7NvR9gIVAyGdzh1IYYpy5VfHGSjNnPajPw==
X-Gm-Message-State: AOJu0YyR+8LuZZx3cH9z/GkBcgWe50hNJCBZc/k/SyjNbP5e761F3+F0
	W225WjqODLuqn0sAeplgs/bA2w0njvbEfqnSXNimBf/6tZHKEFV6
X-Google-Smtp-Source: AGHT+IFDiVu0RuaOsxySTABNm8KAdn950WcK1Kw/HFUezJlPmgzth6juHtt3SBa8Bcjj7mggRfsEvA==
X-Received: by 2002:a05:600c:601d:b0:412:730d:ab69 with SMTP id az29-20020a05600c601d00b00412730dab69mr21008wmb.4.1708450366364;
        Tue, 20 Feb 2024 09:32:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1567:b0:33d:1ee9:b928 with SMTP id
 7-20020a056000156700b0033d1ee9b928ls1941011wrz.0.-pod-prod-04-eu; Tue, 20 Feb
 2024 09:32:44 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVSWNkWRs6pn2MUweVvgFwtsahcde8Wz5TtU5htwBIPpR2ajZqMzcvOCrtZJyeJw6RHfDeQ73iBEkzkJjP82UjqvJH+OBgTiXhWew==
X-Received: by 2002:a5d:4102:0:b0:33d:248e:5b7 with SMTP id l2-20020a5d4102000000b0033d248e05b7mr7270998wrp.28.1708450364413;
        Tue, 20 Feb 2024 09:32:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708450364; cv=none;
        d=google.com; s=arc-20160816;
        b=BfvlJTBLiXtdfmvBnS8al8S30JJXXQ+04nqPv7vi7bH9NzqO2u+uxS464JGYPwnh60
         7lxqRUJmkdKtV0IBB/B6rhxqqzps3t5ba9XOdvwHumZmtiFex7JBKTv9aNChZ7sfZB6E
         4a27c9jf2Aea+Qbox/rTxoUR/tPGc1KqJ8S9GKywU7qvPpeCIXk2kj/MVsALIDEmnerV
         1VU3XLx2Gd9aL8cJ30PyDLKtXBtnjG2KSkip4jYJoJ47W8hmOk/SzMxbpPAWDmxR2e6K
         QDfsc/Bn9EXVvjNmPCnND9bLI6yafZasDRwe+oJhIFlSwgIqaGpU/B6b0TlGx9mJqtuF
         ueKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=OL5xFDTNv2eO4cGs2LE/aYT6r12sFC1afgYu/aCZ6KM=;
        fh=cdnrFe24HzwWdEILUfE8iAnKpZWbuzZYUVYziuBEAhI=;
        b=Sm6Uz9ISFWbYBmugMpLoVWm3+v62H61s5qsKo6Pim0on1ZEjqiO3YFrnjgbC8qW3+f
         j8O8Brm6XQvE14WigNh+QpFQUWndG2Z0VPOftPt1sPnD+UuEVvp2d/FN4SwwE7aEhVbl
         ybRBOkCZfLmbAjVydGz+HmIbQpuL7Rst8inZM3VY2ONRnwCBVSsqj20+OuzmnynNTUTv
         EgZEb3J9Bw6wgSdog0UzZcGjwPq8/275FbBX6ZW9LAOgTCeXbWDXMi9uGTdz9y++GYwL
         Nu34CcyYSGChLqovT5N1joe61vfn2EZipaHBixUSbkM+Z8kD+LHurBZgUJbEy9TqJEDP
         zwVw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=fxyuYm2K;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.187 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-187.mta0.migadu.com (out-187.mta0.migadu.com. [91.218.175.187])
        by gmr-mx.google.com with ESMTPS id o19-20020a5d58d3000000b0033ce867f703si463186wrf.5.2024.02.20.09.32.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Feb 2024 09:32:44 -0800 (PST)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.187 as permitted sender) client-ip=91.218.175.187;
Date: Tue, 20 Feb 2024 12:32:32 -0500
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Michal Hocko <mhocko@suse.com>
Cc: Suren Baghdasaryan <surenb@google.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Vlastimil Babka <vbabka@suse.cz>, akpm@linux-foundation.org, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net, 
	willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, david@redhat.com, 
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org, 
	dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org, 
	paulmck@kernel.org, pasha.tatashin@soleen.com, yosryahmed@google.com, 
	yuzhao@google.com, dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH v3 31/35] lib: add memory allocations report in show_mem()
Message-ID: <jwhienldkk4gfxcv5giaxbphp5irfleo2c2inezaj34xu4gkmh@uujdnks2r5w6>
References: <320cd134-b767-4f29-869b-d219793ba8a1@suse.cz>
 <efxe67vo32epvmyzplmpd344nw2wf37azicpfhvkt3zz4aujm3@n27pl5j5zahj>
 <20240215180742.34470209@gandalf.local.home>
 <20240215181648.67170ed5@gandalf.local.home>
 <20240215182729.659f3f1c@gandalf.local.home>
 <mi5zw42r6c2yfg7fr2pfhfff6hudwizybwydosmdiwsml7vqna@a5iu6ksb2ltk>
 <CAJuCfpEARb8t8pc8WVZYB=yPk6G_kYGmJTMOdgiMHaYYKW3fUA@mail.gmail.com>
 <ZdTSAWwNng9rmKtg@tiehlicka>
 <qnpkravlw4d5zic4djpku6ffghargekkohsolrnus3bvwipa7g@lfbucg3r4zbz>
 <ZdTgWb7eNtF4hLw2@tiehlicka>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZdTgWb7eNtF4hLw2@tiehlicka>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=fxyuYm2K;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.187 as
 permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Tue, Feb 20, 2024 at 06:24:41PM +0100, Michal Hocko wrote:
> On Tue 20-02-24 12:18:49, Kent Overstreet wrote:
> > On Tue, Feb 20, 2024 at 05:23:29PM +0100, Michal Hocko wrote:
> > > On Mon 19-02-24 09:17:36, Suren Baghdasaryan wrote:
> > > [...]
> > > > For now I think with Vlastimil's __GFP_NOWARN suggestion the code
> > > > becomes safe and the only risk is to lose this report. If we get cases
> > > > with reports missing this data, we can easily change to reserved
> > > > memory.
> > > 
> > > This is not just about missing part of the oom report. This is annoying
> > > but not earth shattering. Eating into very small reserves (that might be
> > > the only usable memory while the system is struggling in OOM situation)
> > > could cause functional problems that would be non trivial to test for.
> > > All that for debugging purposes is just lame. If you want to reuse the code
> > > for a different purpose then abstract it and allocate the buffer when you
> > > can afford that and use preallocated on when in OOM situation.
> > > 
> > > We have always went extra mile to avoid potentially disruptive
> > > operations from the oom handling code and I do not see any good reason
> > > to diverge from that principle.
> > 
> > Michal, I gave you the logic between dedicated reserves and system
> > reserves. Please stop repeating these vague what-ifs.
> 
> Your argument makes little sense and it seems that it is impossible to
> explain that to you. I gave up on discussing this further with you.

It was your choice to not engage with the technical discussion. And if
you're not going to engage, repeating the same arguments that I already
responded to 10 or 20 emails later is a pretty dishonest way to argue.

You've been doing this kind of grandstanding throughout the entire
discussion across every revision of the patchset.

Knock it off.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/jwhienldkk4gfxcv5giaxbphp5irfleo2c2inezaj34xu4gkmh%40uujdnks2r5w6.
