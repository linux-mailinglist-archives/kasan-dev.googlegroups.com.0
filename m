Return-Path: <kasan-dev+bncBCS5D2F7IUIJXK5TVYDBUBFNKJBMS@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 8AB51854C04
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 16:00:44 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-511559b30edsf4116908e87.3
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 07:00:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707922844; cv=pass;
        d=google.com; s=arc-20160816;
        b=fDegU/8LRLkPC2HQdg+S7TSqX/C4QK8LOAeLNPbsWfsgEMUTWz67CKMgNARj7UTlBm
         X5zqGqWyNtpJg4VY54ds0WLM76xrtkNVb1pNy+MLgG61W2mEjlsgZpaml4+kk04zU4WQ
         /cL8GtNbm7Lp0DyYBkiTW/fwjX3aY/7n/RaBbLuAjXu1CLO84y7F301btidqPPMycQZn
         NdzfUDxjzAPEoBYEPAM2opCHThX7IB+7P+Fh/RvDaQOB7oQDLpzcA6U6nkFv9Zuzv2y7
         knIaZuZkB5oAetMVNBA/793TNUMUs80cHr/mV+3F2KZocIda/OYcRvceN4RrKDdm7xxw
         1slg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=LvuxHutM8CAJJTGn9pcRHClf6cP+WuKQA7+jgg25jn8=;
        fh=NWboui+eIyutMYH6+8UmhJ0A18QGv9LPO++WgVfWsFM=;
        b=bsWWGlB8iZp9giGyzR8P5DqiPoMhNBzvqqbHqCWLJouzKrfRPoFz0Un/qNGQ8Y0kj8
         YDJTDcJT7Seg81ktnbGhQNweZPjgo9sImO3+A3r6OmKLRvdXju3PoGI9fyJlF603W6g+
         LpR8G2Q0UNfaf6Ctjwi2CBf1RFTsol7kLNxIYUK1uMaO+H5GruGCJhb3aAI/DzukynFx
         T6yKzvpGCjuUrqhiQiVJqdeV0mOQZmYM7z5CjBIvRagydJ3Ui2qHEoZXLN0CSsyEQ/8k
         jEY1UqO+dFYoX23nT3BH5HfoWgeWeTtLixWzXzeSqqIW4HaP/Ndo5lmglBpGbXpnoeoG
         3kYQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b="jfoJ/wmk";
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=willy@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707922844; x=1708527644; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=LvuxHutM8CAJJTGn9pcRHClf6cP+WuKQA7+jgg25jn8=;
        b=IBlwIiq1cu51R0FhGls4bPLQZI7cAJDpa1Hsps4g/KF5Orf7zk7pxjjShghKD7LS6c
         0SdIVVNWjNPcqSVp3ImngrwrwXiteGr6qYTspJW+XCkyG8utXSBAiB6v3la+3mI2e9CX
         gDHG4AfAruWZ+yU/RI/pySFO2CXaxeimNnK1WYqGtzk3FiUgCLdysquuMK1b7sF5D9L9
         fB0BIcgFOBERoJ3DaI3qqKimEnxn1d2TErj5xl/QqoQ6RsyGl95n2FA13XkKMNGS9Afv
         q0ntsOC2vXsUE7Xyj4Mkf/VZkVvhFgfIdvqcH8RIsI5hGkqNMvlZJFuC0Wb/fpTg53kp
         ykZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707922844; x=1708527644;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=LvuxHutM8CAJJTGn9pcRHClf6cP+WuKQA7+jgg25jn8=;
        b=YdITxt5bATL4MXz1TzVfF191i4AAQ/M1wzamGmabFiyByFXhxelZp8dj1hTilmeCjj
         j7mYu+Aq9GjMOw+zTTfXu7v5fHpTyvW4ZaRbF+vSeYjoVd9tB2oHSYCw9uWBPRPRZgwg
         RPIx1i1gCjMKunlGPj9fjwFC4Ozpv2tLgjfw3pDt6QpcoKxQRS6XhECvNEbp+8zQGzHl
         nNhHsDD4Y3AkK0GOy+T6iwaCLd+Ey9s5SY4GswYTIHDYGEzrMNFtl7LXo6X3ajuLzMAD
         aipnNhGwGvcs636b/I7XQV4JwufDfSLrbTKkDwQzFPAss3AupLAGxaPln8m+g27Dc2l9
         bhGg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXhCt159ubvn+EZC7Iavi39QzsgMaJ3D6v7pecAd4UqkfPenwQgE+XecRa/G2OaMu9kOfMgFBL0rZsFndBrXYGHB3oeBFmiVg==
X-Gm-Message-State: AOJu0YyXTCRfvxX/OUD4EMNArpryU7Jxvsw3061nkj47XD8KD/NaRs5O
	va5A56wiQzKuhbX3hgyycFQ2wGzGctC1aCgwpk4E5Vn9yoOd5kxXgJQ=
X-Google-Smtp-Source: AGHT+IGLt9095YRymy2YGrxQNxvfO/yctolZxkLXlhMJORqLGHMM1ICi9+x02y2oZ97DlTO+Vs7SFg==
X-Received: by 2002:ac2:52aa:0:b0:511:86ce:3920 with SMTP id r10-20020ac252aa000000b0051186ce3920mr2152388lfm.7.1707922843479;
        Wed, 14 Feb 2024 07:00:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:350c:b0:561:2701:7dfa with SMTP id
 b12-20020a056402350c00b0056127017dfals189392edd.0.-pod-prod-08-eu; Wed, 14
 Feb 2024 07:00:41 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXwCIafFvlUt69y1QHSMJpRJwYpl6UrBYr2IWgnowTzuUERS9s+4VtCZJVSIJ+c5aIhRlCpkGP1vMrjIEy9FW5+4ZgFQ7OyySDqmg==
X-Received: by 2002:aa7:d3da:0:b0:561:c6fa:715a with SMTP id o26-20020aa7d3da000000b00561c6fa715amr1968271edr.40.1707922841450;
        Wed, 14 Feb 2024 07:00:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707922841; cv=none;
        d=google.com; s=arc-20160816;
        b=Ucp0lYeAlLZw8SgxPZQBv4Ib+3HE1QzBAg7Tq9ww0l4RBv9YGjc5iMtOb3GBfRzhth
         J1dHwYJUE0uluA0RL6OkcCslVHR7MgdnQjk/L+n0iZJtdj1nEQmizkaND8FBKZrdPSd7
         gJ4k7mlUsacV9tOeIH2eLRvy8hQnAIwmbHZfDAVl1CZbKyEKXWoLsZK0w4xoolCu0k+r
         N6hBY24bMTSNNQpwBdxwcYBzi9mV5fVNeG5NFKbPX/mqBuuH7VPrmz8rOCbX3sazXqaN
         jAJEgGj00nf8UKOKRPGJVQ0BFc1yW1YRg+56QSY2NqqxzsLgi7r5/OPZY6H+CWrxgSHI
         7ENA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=N9oS2vBFsBe7fjNywvimN9eVDsY+Q1p8TnsuDCbqyL8=;
        fh=jaor7rTrJqTa42V8pUUml/L0iBMBQVr7CWm97HY7uI8=;
        b=RNe/bQ3s7LXHQ78L3YW/tRQJKo5QGF4J6AMNCm86UMTINd6QK7Dujb9CMNMA5pVGst
         YjsGoSHMtSLLekIafKWheT7PQz4O2pH85ZniI3L7BCO7NM0nZADzSN1EpKCT3E6Pwwau
         l+M7kZZWeKsE/RSkr3vOmIdxwgTKcJt9Fewup3p4BMDcC3RgByjalxXwUHiK9+Xc3s2W
         i5TgEV9lhF5UqvTv/qxq6iT1pDaiNVL4vc/8ViBFPaY76yNewtfsxAUXhdrmoIvdpWHN
         SGIBCzvCRlBczf8IyJEnZMKvaZbDupDbBB0iRs4qFw7Tftvpe2uNoh1Hx+U0ERh0FLOk
         qguQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b="jfoJ/wmk";
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=willy@infradead.org
X-Forwarded-Encrypted: i=1; AJvYcCXuU0KzphTsZc6RVn4al3vkyq8PIQ3Uit175IVh/CIaafqxWGdprY4TYO9i1Bd4BQn01UPvORv6F7Ph0RqunvCa1DbuVN/qJLHi8g==
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id y3-20020a50bb03000000b0056385533e54si77423ede.2.2024.02.14.07.00.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Feb 2024 07:00:41 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from willy by casper.infradead.org with local (Exim 4.97.1 #2 (Red Hat Linux))
	id 1raGjw-0000000Gs4u-1uPd;
	Wed, 14 Feb 2024 15:00:00 +0000
Date: Wed, 14 Feb 2024 15:00:00 +0000
From: Matthew Wilcox <willy@infradead.org>
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Suren Baghdasaryan <surenb@google.com>,
	David Hildenbrand <david@redhat.com>,
	Michal Hocko <mhocko@suse.com>, akpm@linux-foundation.org,
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
	mgorman@suse.de, dave@stgolabs.net, liam.howlett@oracle.com,
	corbet@lwn.net, void@manifault.com, peterz@infradead.org,
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org,
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org,
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com,
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
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
Subject: Re: [PATCH v3 00/35] Memory allocation profiling
Message-ID: <ZczVcOXtmA2C3XX8@casper.infradead.org>
References: <Zctfa2DvmlTYSfe8@tiehlicka>
 <CAJuCfpEsWfZnpL1vUB2C=cxRi_WxhxyvgGhUg7WdAxLEqy6oSw@mail.gmail.com>
 <9e14adec-2842-458d-8a58-af6a2d18d823@redhat.com>
 <2hphuyx2dnqsj3hnzyifp5yqn2hpgfjuhfu635dzgofr5mst27@4a5dixtcuxyi>
 <6a0f5d8b-9c67-43f6-b25e-2240171265be@redhat.com>
 <CAJuCfpEtOhzL65eMDk2W5SchcquN9hMCcbfD50a-FgtPgxh4Fw@mail.gmail.com>
 <adbb77ee-1662-4d24-bcbf-d74c29bc5083@redhat.com>
 <r6cmbcmalryodbnlkmuj2fjnausbcysmolikjguqvdwkngeztq@45lbvxjavwb3>
 <CAJuCfpF4g1jeEwHVHjQWwi5kqS-3UqjMt7GnG0Kdz5VJGyhK3Q@mail.gmail.com>
 <ea5vqiv5rt5cdbrlrdep5flej2pysqbfvxau4cjjbho64652um@7rz23kesqdup>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ea5vqiv5rt5cdbrlrdep5flej2pysqbfvxau4cjjbho64652um@7rz23kesqdup>
X-Original-Sender: willy@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b="jfoJ/wmk";
       spf=none (google.com: infradead.org does not designate permitted sender
 hosts) smtp.mailfrom=willy@infradead.org
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

On Tue, Feb 13, 2024 at 06:08:45PM -0500, Kent Overstreet wrote:
> This is what instrumenting an allocation function looks like:
> 
> #define krealloc_array(...)                     alloc_hooks(krealloc_array_noprof(__VA_ARGS__))
> 
> IOW, we have to:
>  - rename krealloc_array to krealloc_array_noprof
>  - replace krealloc_array with a one wrapper macro call
> 
> Is this really all we're getting worked up over?
> 
> The renaming we need regardless, because the thing that makes this
> approach efficient enough to run in production is that we account at
> _one_ point in the callstack, we don't save entire backtraces.

I'm probably going to regret getting involved in this thread, but since
Suren already decided to put me on the cc ...

There might be a way to do it without renaming.  We have a bit of the
linker script called SCHED_TEXT which lets us implement
in_sched_functions().  ie we could have the equivalent of

include/linux/sched/debug.h:#define __sched             __section(".sched.text")

perhaps #define __memalloc __section(".memalloc.text")
which would do all the necessary magic to know where the backtrace
should stop.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZczVcOXtmA2C3XX8%40casper.infradead.org.
