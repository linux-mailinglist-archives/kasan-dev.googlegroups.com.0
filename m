Return-Path: <kasan-dev+bncBCU73AEHRQBBBXW4XKXAMGQEBEMZ4RQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3e.google.com (mail-oa1-x3e.google.com [IPv6:2001:4860:4864:20::3e])
	by mail.lfdr.de (Postfix) with ESMTPS id E708685729C
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 01:37:51 +0100 (CET)
Received: by mail-oa1-x3e.google.com with SMTP id 586e51a60fabf-21e2f43d27dsf1345770fac.1
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 16:37:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708043870; cv=pass;
        d=google.com; s=arc-20160816;
        b=T/wbtYmyVcNqBW48Bdnx0VnuX/ZTUXTOECguxLsEPYvH1IOQOU7u/MTJZMB+z63pYC
         PtHQ7NYD1+hZqlcB4fp3qMo0uZaZT2b6CQBocXUUjz8cthvX0oz3I8umKm0dW8RKR1wE
         KgryoNnAVCnezwFA9+kXGJV8WmOP1ErRQuMMQYoMMWCiHmj0kRqQWSIb9kBiPuk1aXp3
         YqTtLkRP4iznahtAZHqapAm56vLTAuzN8Gtil9XnRvzO4E11hRUHUgRobqb/liG4MY1+
         FNMCPSQuKm21JIacAbvuw3WjEyXZMHHPX+RKMsjfUOYYdyEp9iwBordqLFZ/mpNJKO0d
         wfUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=w7k6GCVKFmqJQRqb5o3iLUGf5WAa0VTuIPiFG4/kulc=;
        fh=yYKCZhEMT/hIy8LViOWDQIioNrcbGgJfQ60RdZlL8Bw=;
        b=kBWeBTYlSkkmJWPeR2+6OMBIjPp7HPcJyuAHnAs30DJF6pmm1GSjBI/H0PZGMufery
         nTb0oo5DuAoGW5XHbpbY77FPo25Lyy72vxjy0d36VmCpBjnoaBPEvrDxK1WAhod6R7cc
         hX0vq6cFFyEu9UL9NWIadDy8fQRvVBTA44rG88Wr76P5IgYKUe5iMJKDCZrGEilN3Ujn
         xhQn6TYGxObw8y/nfSNVLe/OQ770WF15eEr3W6oUrbv7CSSX9co+iN3XqCUNWPI4L4hK
         zl3S+BkSOU9eq+lOl+qYuLeYRkY3SKgqmyF4aKWTLPvoKAe3IZ6DxpgO2gQICto1Pb1/
         06SA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=rkxr=jz=goodmis.org=rostedt@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=RKXr=JZ=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708043870; x=1708648670; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=w7k6GCVKFmqJQRqb5o3iLUGf5WAa0VTuIPiFG4/kulc=;
        b=qOtN5aL88zKdtA25TjPy2vYiXAYqCRowfkDsKgSal4b06Cg/85ji1nsxV5NqTyt4Pb
         0dDq0AzuI8/13JBA+ddYiBT4HI73AOcqP0khORRtSgUHEqvrp20cpqAgrA6EE4UeDnrZ
         YFLwu7ipq8JAluLp8SMeubBg7dvCQWqiNDo3V9RABsBvYpkObPGGbB3QBY+Bo19ae/ax
         EbkSHVYgtsPfxBqKMEFxfhHxEbuzJZ0fhFhumfe9dB74fXbJdhBTCrPgZRE2Iw9XO0cr
         3GiMNSgX3e8G4yHtLIekioBmhijw+L4IN9JbJfMrQCSp0hgBmmqHKM+zdcEOor7FInha
         Pjiw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708043870; x=1708648670;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=w7k6GCVKFmqJQRqb5o3iLUGf5WAa0VTuIPiFG4/kulc=;
        b=dbL13ZUXzkuLAKtRjAc2MD+9zeJ30aLbOmRL95QwJUIJZddiJV5OGEoMioKYAjvIro
         nr2Xzyoh1ztgBplFjs7LDUZPDpddYVBiM89l8EMAh9OajYyWgwjGkUPEBU6lLK6LM86X
         uulyFpo84LV1kNQ38W6VCLipJVtC2U8xzDZ/lQRiTuYFZmF2KP1EvuwLKXidHEKasFs2
         33g9pI6zM6EZyJE5nh0/J/0vbow4tmkaU+2+vVDivDRFF5/RtF9u05J9NCglbagUekhf
         zJWlEzLIGen7Ym1yNsrSpa+Ma2bEbkcFb7zI0QusteFarhe94SLIKlk8Z3tUZ+vvt1WP
         4YjA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW/eOkBbF4wTnCA22ib5bMWcmfI6iis1FpiFlG9UfFZ4XcMNZdNcgTX5ZYz9lLZbj7wQZecGoPnRTb0rWpsN1ntKQ6JFb65Lg==
X-Gm-Message-State: AOJu0Ywz8zusOGjLZbDUpTY5znbBb1XPot5nvpfEHxrQPjiJZEMoMr0m
	eWOmR9NFIN6/Iri7ZwRbvOgBDojCCOoDuDrZAor/V2InakUNBMmK
X-Google-Smtp-Source: AGHT+IHaH5/txKGGd/SgGfLCHQU5l5eZBWwR2SPMzEpb7mNJCpOB/pP8q4G7xlfmKqsJeoOS+teGyw==
X-Received: by 2002:a05:6870:63a3:b0:21a:313e:278 with SMTP id t35-20020a05687063a300b0021a313e0278mr3653396oap.4.1708043870770;
        Thu, 15 Feb 2024 16:37:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:b494:b0:21e:40f6:4f8e with SMTP id
 y20-20020a056870b49400b0021e40f64f8els355323oap.1.-pod-prod-02-us; Thu, 15
 Feb 2024 16:37:49 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWniu3YKFTTBemlSkfN8RtQP5kQeFyxExzi58Ox1ZVh6Np/CuYIJFwQwl1orglxNuxfhKmMBb9ZE76Dq+t//vWjOiZ48/T6LfVOBQ==
X-Received: by 2002:a05:6870:d202:b0:21e:6669:c3b4 with SMTP id g2-20020a056870d20200b0021e6669c3b4mr50749oac.35.1708043869584;
        Thu, 15 Feb 2024 16:37:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708043869; cv=none;
        d=google.com; s=arc-20160816;
        b=y0ZeYn7TkINi82D1Nj6iz7tCLV4hgJuwZMCstt8u3te/aaSaXjfrRxiXd+dPbOqG8n
         3hBbHveUnIGEPlK1ZcQVpD6eW53iq/fM20AmzhM8KB5uhQKzfz+yq5YPWiF7JfDtCPMi
         QQWIVv2cqjRHxoLee69f6nwKIbGA7E+uwIGgxW/6Syg/imyN8ztbz0LF7DPN8rfs1EUf
         M+vuuFT9GORcuMAJLiOhFCD5PgjmEQUgLsDfRYhG93OpoTtDjG4jENmuclILnkNYd3LW
         0qVWTnQ9JwC4V45Qu2//y/wN/V+VukpX7fawXyBpL4Z8PhBjtu4kWSn4ZVExFzvYI28Z
         5A+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=+nmqn9S1ASKA4C3uwsYXdX2JCiejoSQYXEKqWiLf01A=;
        fh=yAsR8mz6OHt7FqUIcMxTq2xSLRkYQrfOXi2SdkYqlko=;
        b=0FM6Djpa6J2HbFXadZSgqynQ99oDyHN5XJ5KhOHiLE55++YkMekTEFATAcJ+XaQz/7
         6j4VVUng0B51moxfXkBKbA0LmTwGzf3fRvvcB9dlzOZDsGdkF8UraZab7827BXkWJEud
         xBxUkfFlDANkQ0MBd79xOxnJ9TBALeywOJ/17JAZYvk7wC6ExoLgFYXW3FNc54tsprU2
         jbt2CulzB+XehqUs2ywHqzxB3w+5Q7Z7gyDoZgA3JTCel9tfb65q3R2eHB0I5PAlpNWp
         U+cYm0hrzsCmOxUp4a/9ZfCW4gOFgu9zUg9CqNipwa4cuEUPKCrfd/C/lv9rwR2qhdw/
         9WZw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=rkxr=jz=goodmis.org=rostedt@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=RKXr=JZ=goodmis.org=rostedt@kernel.org"
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id n125-20020a632783000000b005dc96170159si214912pgn.5.2024.02.15.16.37.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Feb 2024 16:37:49 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=rkxr=jz=goodmis.org=rostedt@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id AC493614FA;
	Fri, 16 Feb 2024 00:37:48 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id ED6A9C433F1;
	Fri, 16 Feb 2024 00:37:40 +0000 (UTC)
Date: Thu, 15 Feb 2024 19:39:15 -0500
From: Steven Rostedt <rostedt@goodmis.org>
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Vlastimil Babka <vbabka@suse.cz>, Suren Baghdasaryan
 <surenb@google.com>, Michal Hocko <mhocko@suse.com>,
 akpm@linux-foundation.org, hannes@cmpxchg.org, roman.gushchin@linux.dev,
 mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
 liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com,
 peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com,
 will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
 dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
 david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
 nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev,
 rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com,
 yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
 hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org,
 ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org,
 ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org,
 dietmar.eggemann@arm.com, bsegall@google.com, bristot@redhat.com,
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
Subject: Re: [PATCH v3 31/35] lib: add memory allocations report in
 show_mem()
Message-ID: <20240215193915.2d457718@gandalf.local.home>
In-Reply-To: <uhagqnpumyyqsnf4qj3fxm62i6la47yknuj4ngp6vfi7hqcwsy@lm46eypwe2lp>
References: <Zc3X8XlnrZmh2mgN@tiehlicka>
	<CAJuCfpHc2ee_V6SGAc_31O_ikjGGNivhdSG+2XNcc9vVmzO-9g@mail.gmail.com>
	<Zc4_i_ED6qjGDmhR@tiehlicka>
	<CAJuCfpHq3N0h6dGieHxD6Au+qs=iKAifFrHAMxTsHTcDrOwSQA@mail.gmail.com>
	<ruxvgrm3scv7zfjzbq22on7tj2fjouydzk33k7m2kukm2n6uuw@meusbsciwuut>
	<320cd134-b767-4f29-869b-d219793ba8a1@suse.cz>
	<efxe67vo32epvmyzplmpd344nw2wf37azicpfhvkt3zz4aujm3@n27pl5j5zahj>
	<20240215180742.34470209@gandalf.local.home>
	<jpmlfejxcmxa7vpsuyuzykahr6kz5vjb44ecrzfylw7z4un3g7@ia3judu4xkfp>
	<20240215192141.03421b85@gandalf.local.home>
	<uhagqnpumyyqsnf4qj3fxm62i6la47yknuj4ngp6vfi7hqcwsy@lm46eypwe2lp>
X-Mailer: Claws Mail 3.19.1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=rkxr=jz=goodmis.org=rostedt@kernel.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=RKXr=JZ=goodmis.org=rostedt@kernel.org"
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

On Thu, 15 Feb 2024 19:32:38 -0500
Kent Overstreet <kent.overstreet@linux.dev> wrote:

> > But where are the benchmarks that are not micro-benchmarks. How much
> > overhead does this cause to those? Is it in the noise, or is it noticeable?  
> 
> Microbenchmarks are how we magnify the effect of a change like this to
> the most we'll ever see. Barring cache effects, it'll be in the noise.
> 
> Cache effects are a concern here because we're now touching task_struct
> in the allocation fast path; that is where the
> "compiled-in-but-turned-off" overhead comes from, because we can't add
> static keys for that code without doubling the amount of icache
> footprint, and I don't think that would be a great tradeoff.
> 
> So: if your code has fastpath allocations where the hot part of
> task_struct isn't in cache, then this will be noticeable overhead to
> you, otherwise it won't be.

All nice, but where are the benchmarks? This looks like it will have an
affect on cache and you can talk all you want about how it will not be an
issue, but without real world benchmarks, it's meaningless. Numbers talk.

-- Steve

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240215193915.2d457718%40gandalf.local.home.
