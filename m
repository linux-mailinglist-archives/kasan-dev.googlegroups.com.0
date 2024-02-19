Return-Path: <kasan-dev+bncBC7OD3FKWUERBPM2Z2XAMGQE7HX4H5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0825485A9B3
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Feb 2024 18:17:51 +0100 (CET)
Received: by mail-oo1-xc3a.google.com with SMTP id 006d021491bc7-59fbb444bacsf2432368eaf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Feb 2024 09:17:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708363069; cv=pass;
        d=google.com; s=arc-20160816;
        b=WPX8wHk+EdJWJK2WIHQoMXtNe6LR/guCv0lRj1oEq86FTqnoMuEGsKu66CVbZGaLCj
         qTJl+D7KGRJyF6i3gZL6vKOZ0s4nHodTOMYCsjYNw94czuxDeqEh0F1WpbT3BKaPb4rU
         xmGpBgiO09V1M/1TCpStR64+eczY3iCoQf/H3vclcTVrUNTmzAuGIAD92MeKza8MDTEc
         eA7sK8YJk56ab1me3ujThXD71kI+V7voy9+53KcjjuwrXQUTsFMshxjzaqmydtxTcjAU
         0QW3+y7YDMeSo/HuIAbWKkmaSfgHRliewXDKtgm59P6pKLN+ZvL0xkkkUtZXi+sjqKKv
         Ei7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=TYvemYpYAM/amDUZpoDCb8htCoT3yj4+OfJvf2RDoJc=;
        fh=sVRKvR2K3i1fJ2Ti6U0GVzxVlW52dNP3hlk9HfP/pe8=;
        b=ND7bUEtgZCeBxlsaPfJ58Oe+x7+E2MGZFaqvI6gx+2dDhrVK4BBKlaozhwIMNsuz1W
         nEK60zzFs5hQrY97jfsqHpeFX/MneVE4ImW6VW418bdYBo8zCrNw/HU7ysiZlZYkJuXd
         PHcbG22ZuRvVzV8fTg3JIs+fvauXowKvbhc7Xg7Z8dFCyV2jIMguhi4CAAw3XDguHq9p
         0bCEkHd+nmCVf/A6N+50YP/3f2UfsgIbmhfC9lfPy6YL89S1zK3oL0d39d9fnq3+RM/9
         3xTyjAi6Vn81IBQKLQaTGnLVVB7VIJNp3tnPC8xchdwqUkA+b0gf6dI2J50Fsm6CULpA
         pkJg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=JZyHlg54;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708363069; x=1708967869; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=TYvemYpYAM/amDUZpoDCb8htCoT3yj4+OfJvf2RDoJc=;
        b=sklwWF9KfnSYVxi5jUiG0MYSEjUZJnhuPTrI+YiL5uD1dpuYXoSoxTA2lFMbIL1mBb
         QHgIA+dsHBJsgFFTxAEVujR8mApwnBoRiSjRs0ud9xBVoSVImWnwCh2f3UYgZRbyxMur
         JITeIjVwEx7zCJ4EU7HGoYgHhNdLT0raMlPbZlBFbOownUoLmN21EAlu+l/Kess1mCob
         t1ETgBkQv5H7WvnfB+jOqzSfgo33IOxOTLbiluOW/MqZ4AnIrPZR9+tcpSrG4Xeucmye
         iJGzmEI8Q5fyk70HvbLgNtRg7fnDv8RY9yHzSL+BLG2Rz0CAqFSAJg1l5hNWK7mH+sY/
         w/UQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708363069; x=1708967869;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=TYvemYpYAM/amDUZpoDCb8htCoT3yj4+OfJvf2RDoJc=;
        b=J5sOwXWE/ELHOv+flJoZzGiRIuJEpsn1E7mD5VuF5DFEcP63Cz+zW7gCFe4D965QWv
         gPQwDiIKqds++/v51LzoJiA1WRiQ80Jigv3yiJiGlFs2RhgBK3R3zJM3YkXs+B6cDKyo
         pnPI+oDnzSd3z3Zdlnx6mAAdxM/WSD+PjtS22jSSTJ4p3fnfc/hmi7NhR1ZSqWpmZvQm
         ZovGOHenWg1tVBbM8CRztVCvhsp1uG1Zo/sWSc6JNraJRQVjo9uByQe1f0BbFhG8VAc9
         NKH1gDFmxewyfIVgYlipPi8JAZIpg0Ku7onGSi/HwyvUB4GuqFXi+ig6NZwXBj74EwQG
         b8Dg==
X-Forwarded-Encrypted: i=2; AJvYcCWOeJ7ubRAyRmGwivxAF8lpcYUQDa8LrTyOxe22xylYEhe8VZW8JWPSv4kWjzAnd1p7+PxYT3gCHP7iU+firybOX9AIBvP3nA==
X-Gm-Message-State: AOJu0Yy2hRNH3HYAeVuvAUJi/m9C9USVSvHwTpvy0u6XLa/emITQMjT4
	/VjTizpyA45bGDR58Y3JlI/Dbb+jsimdQOXbPhayY6deXuTJa9Bz
X-Google-Smtp-Source: AGHT+IGY7OrYsiwlfsb4sEjBMjfOBkYsDUGvBHLd1ejOwVhrUMZYh2b46VdLPU3D7+sHIB2IOaXAOw==
X-Received: by 2002:a4a:dfd9:0:b0:59f:dcda:d6cd with SMTP id p25-20020a4adfd9000000b0059fdcdad6cdmr3459966ood.1.1708363069606;
        Mon, 19 Feb 2024 09:17:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:5703:0:b0:59a:85c:a968 with SMTP id u3-20020a4a5703000000b0059a085ca968ls2089402ooa.2.-pod-prod-04-us;
 Mon, 19 Feb 2024 09:17:48 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXG3briWgCfHzDWXN+HJXYQAQmWYWHv4O41Eim+tWJ7C6E1UHccZhHH0mIJZkihtOdkwCwX4f3Y9nRNNaGIHCy+j9GfIU4po8oUSA==
X-Received: by 2002:a05:6808:2388:b0:3c0:4129:9467 with SMTP id bp8-20020a056808238800b003c041299467mr17074393oib.0.1708363068718;
        Mon, 19 Feb 2024 09:17:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708363068; cv=none;
        d=google.com; s=arc-20160816;
        b=w2P+rqXK/h4IMCSu6dnwdFvjGydRCza4HW0lYt5QejO6quSjMKPMp1M3RQTIasnqfr
         SsoT1fb2d26vP89skbQiST9pQrjzXY5JeRTEnnL+iC+MtP6ZJsZFxdAXBrbz/Q1RIJMS
         p3qKYphZ4V3uu9vZ1nknoH9ffWcpRRM7bmQyYHNI7beHbHQDma+FV2DWAswmOCQD/IMv
         DHiPUYy0yZUsqwq5BZQ8rqv9W3T41rdUcGKCzBKJ8D1dC3EpD49+Nj228UaXKO4LcCQC
         ojBT0cX0tFfYaksvUevKLMe665QBDc7/k+V3zgOB8m/TMiTZf/yBvWKn1+z3Bo/uHNGs
         qfZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=WTUgtDUhgLo3w13qAUwpQFiIiTT2/XDD2PV7WnKy99s=;
        fh=TI6mpXEnneaNsKSqFgrXLaci5y0NO9n+ORk+Q42EE9Y=;
        b=XK4kzEq99vkbMC8uFXtM6Dm631U9tBhQG6Zz07744W0K5j1YHLMSjBLDQDnELHKjjh
         uvYIVwNGf89f6fIP55/ELFmhRoscxB0a3JsXuLjxLhSL2HCDRs1Jy1CAxjCIvxsrYXUJ
         tLKh6XhnxU9D9hI0UvfavjMZNLurBn6qxI7GhMP3u5/UMYwuH4chLFd+kytJqiWhW0fL
         LDbB4Lse2N1SByj181YZF1AcfDHMfmn6zjGodzqmLfcVAQLFSzLY+aU0lLDaN6U0hDqK
         79ZqRk/stxQYInGnVk19Ec0gz1562hrzRbD3jQiY727NdgkJdrsAiVrrPiK47neHH2Ze
         O/dQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=JZyHlg54;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1132.google.com (mail-yw1-x1132.google.com. [2607:f8b0:4864:20::1132])
        by gmr-mx.google.com with ESMTPS id bf35-20020a056808192300b003c139323fcasi416338oib.3.2024.02.19.09.17.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Feb 2024 09:17:48 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) client-ip=2607:f8b0:4864:20::1132;
Received: by mail-yw1-x1132.google.com with SMTP id 00721157ae682-6083befe2a7so11280527b3.0
        for <kasan-dev@googlegroups.com>; Mon, 19 Feb 2024 09:17:48 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWJu7sgCSdsUiVD757ngiUKg2ukl7QnBkCpcfqFNaV99PqZiyJICiDTe6alaCNeHWqCXqIzkQ7AkvBAhstCjPZkPjqVttCLhirffw==
X-Received: by 2002:a81:9b02:0:b0:607:9613:2afa with SMTP id
 s2-20020a819b02000000b0060796132afamr11401400ywg.0.1708363067747; Mon, 19 Feb
 2024 09:17:47 -0800 (PST)
MIME-Version: 1.0
References: <Zc3X8XlnrZmh2mgN@tiehlicka> <CAJuCfpHc2ee_V6SGAc_31O_ikjGGNivhdSG+2XNcc9vVmzO-9g@mail.gmail.com>
 <Zc4_i_ED6qjGDmhR@tiehlicka> <CAJuCfpHq3N0h6dGieHxD6Au+qs=iKAifFrHAMxTsHTcDrOwSQA@mail.gmail.com>
 <ruxvgrm3scv7zfjzbq22on7tj2fjouydzk33k7m2kukm2n6uuw@meusbsciwuut>
 <320cd134-b767-4f29-869b-d219793ba8a1@suse.cz> <efxe67vo32epvmyzplmpd344nw2wf37azicpfhvkt3zz4aujm3@n27pl5j5zahj>
 <20240215180742.34470209@gandalf.local.home> <20240215181648.67170ed5@gandalf.local.home>
 <20240215182729.659f3f1c@gandalf.local.home> <mi5zw42r6c2yfg7fr2pfhfff6hudwizybwydosmdiwsml7vqna@a5iu6ksb2ltk>
In-Reply-To: <mi5zw42r6c2yfg7fr2pfhfff6hudwizybwydosmdiwsml7vqna@a5iu6ksb2ltk>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 19 Feb 2024 09:17:36 -0800
Message-ID: <CAJuCfpEARb8t8pc8WVZYB=yPk6G_kYGmJTMOdgiMHaYYKW3fUA@mail.gmail.com>
Subject: Re: [PATCH v3 31/35] lib: add memory allocations report in show_mem()
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Steven Rostedt <rostedt@goodmis.org>, Vlastimil Babka <vbabka@suse.cz>, Michal Hocko <mhocko@suse.com>, 
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
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=JZyHlg54;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1132
 as permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

On Thu, Feb 15, 2024 at 3:56=E2=80=AFPM Kent Overstreet
<kent.overstreet@linux.dev> wrote:
>
> On Thu, Feb 15, 2024 at 06:27:29PM -0500, Steven Rostedt wrote:
> > All this, and we are still worried about 4k for useful debugging :-/

I was planning to refactor this function to print one record at a time
with a smaller buffer but after discussing with Kent, he has plans to
reuse this function and having the report in one buffer is needed for
that.

> Every additional 4k still needs justification. And whether we burn a
> reserve on this will have no observable effect on user output in
> remotely normal situations; if this allocation ever fails, we've already
> been in an OOM situation for awhile and we've already printed out this
> report many times, with less memory pressure where the allocation would
> have succeeded.

I'm not sure this claim will always be true, specifically in the case
of low-end devices with relatively low amounts of reserves and in the
presence of a possible quick memory usage spike. We should also
consider a case when panic_on_oom is set. All we get is one OOM
report, so we get only one chance to capture this report. In any case,
I don't yet have data to prove or disprove this claim but it will be
interesting to test it with data from the field once the feature is
deployed.

For now I think with Vlastimil's __GFP_NOWARN suggestion the code
becomes safe and the only risk is to lose this report. If we get cases
with reports missing this data, we can easily change to reserved
memory.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpEARb8t8pc8WVZYB%3DyPk6G_kYGmJTMOdgiMHaYYKW3fUA%40mail.gmai=
l.com.
