Return-Path: <kasan-dev+bncBCT4VV5O2QKBBJGUYSRAMGQEUUCR3WA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 304776F46E5
	for <lists+kasan-dev@lfdr.de>; Tue,  2 May 2023 17:20:06 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-329572e5abesf62325285ab.2
        for <lists+kasan-dev@lfdr.de>; Tue, 02 May 2023 08:20:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683040804; cv=pass;
        d=google.com; s=arc-20160816;
        b=tGJq4B+y+TUF3eEu45kEG3rqFAgfdTVQ11BZz6c51LjOOIUpgVw9yre2p4Of/Oco+X
         73PtXh47EyUoywSuGVDRgTgiOBmfHHHNeiU8zDnnlsc9gTPoYJAvmjVW3wwXtAUcHEow
         /45THhmxRl24c0oiF3IAngZv+mwiuwefV23BEBF6qn8/6aIZClCn45HFmD7116XI5j/X
         QvkUqfRKc7RENZp5Qu03cnZ7t8Vo0G6KtWi66YSzRK1461z9ptTfmawikqew552vvM/8
         PAFXfruLl5eGoZ1q4qJsv8gZG+XpfVD8T4axUeLyQGSqU81CBH//LV79/Jr0VaPBNw2y
         WgMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=8ZTzBNGdMK5b2CBbfpjpLVe1kkXRt7FDcGHmcENyrWY=;
        b=rQhG4j9u5idvC25cscLmC4plsVb+cMQ7SGFHp8LYA/uIWe0JX2II8/1qLjfPxLPtD6
         1358sk7Ls9dLc80lfyrzONCpHrkuFOY1xcxwAbap2ghprIBiMdCNRxBKTrHnaLK+BkqB
         lr41wNQIdushfn6VbXN6mcdh9i+VBr1SwQCNGGYyLp6TxHhWa+k72CJlJyeIiXXAoYUu
         9gZLOaP2jTUQOf0E6SDlg344MaL3xTMSn/lIwRKYPFk7e/9v5lo90HGsoBMfJX1h+L7Z
         VAE/wjDMrXps7124QXxT6dVbzwAqQfHfuXLKGcILz6ft7YBzmTRiH/fHePfb+TLuq1QY
         hn7Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=fQDTcAPB;
       spf=pass (google.com: domain of andy.shevchenko@gmail.com designates 2607:f8b0:4864:20::f35 as permitted sender) smtp.mailfrom=andy.shevchenko@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683040804; x=1685632804;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=8ZTzBNGdMK5b2CBbfpjpLVe1kkXRt7FDcGHmcENyrWY=;
        b=Fg1bTrcrmLUhc/oG6dBOw2awkdZaMvxbvnlk7oNK3GuX2USzEKsjBGmAjlY02TPcxO
         O36UrZn4N9sgp6+oU6EgCyfiAkNbbc5b6ADvxIji4kxyjE6r+MMEBYoM2HTWV0zHmq8m
         BO9iHnUbSG9sKzaUqhd4hNAhwA1inKNpkha6/6law/CGUNYTpj2i6RhknN+50ffDJrx5
         RHNi7gKybH5YBjVDgCO6QeSaXeWcKKCEQC6ea0kD6vahZdY6FxFo4Gdc0LkTvZ+wBDe+
         gTavBC1hmRE6wC+WeO/gkn0fomHDGXyjbjS6immvg8iIY/4OECWME+UgWvg6G9KnRb9P
         SUMA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1683040804; x=1685632804;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=8ZTzBNGdMK5b2CBbfpjpLVe1kkXRt7FDcGHmcENyrWY=;
        b=IXUzSnlm9Ru3oqCYKoF4T/K7sO8iDStLUM+xffpdsYQT+1+9nCHcw2Vjk6NR4N47LH
         /HNL9IxY7bh2+iXOrIYJ0dYpYpXzN0NkPr3rAEXgSyIGTMF0wPcZyOtG/6NB581ei6g6
         9HNAhXy0K7H72As6YFiGSw37ZfCvZhdoPjNuBqDR/Bjp7iaeMPuGWPM30bHg1FDdPA4Y
         wSO6CGM9BJ0hvumiOSEJvS7YhqZ6g2rPW2vnbr4f3M/oFC1u9k6P/jC2mMD0lJUhvYBQ
         WSY/P4VYKcf9pbngmJ+604ev8UPK7cO/6weyWo343AN1RL+4CvkzbQ3t+S62HkYIStzA
         yniQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683040804; x=1685632804;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=8ZTzBNGdMK5b2CBbfpjpLVe1kkXRt7FDcGHmcENyrWY=;
        b=Wh4V5cHXF8BUUyJwt2zUBb8/d3U/jiNyIYWDMMrNDqs4WJXpbsBWb3RR1BzXbZ2TmE
         W8mypO8sVo6mmlnd1PquW3ypuendYh+BjCd4f7VfOEyzZiBVpFmRUt3egW3/byzXgSr2
         B/96SCGhPsUPUjvOw5UTy+34H5wmZk2VJLjR3sXLWYW05/ttkFcyhQxvWtv7d5TTxy0C
         tQpti7wT77hkB/oDrKyEPdqT6fmUJTaNYPmmOOpScMZI/cz8p92QCktZoqbnKFpZ7MQa
         DGpiyy4FJYGVO/LWoZDLfflBfv2Tt+w1aoFCSL+4k4Ks2zE7AiUFWIERtDGX15Y8cqkb
         7p8w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDxXv/20O0mYhMa+iF/si0RLPNbwmULm81NNV12NKD15sYsvidir
	gTLZfUfz2hbvvO3upLbrwew=
X-Google-Smtp-Source: ACHHUZ7WXKrrsyE6YQxtFz3NaUymamf66qH8IGD1yGsr5nlBMrbbjqJlcfkNEzsktZmpeWc1SUxJlg==
X-Received: by 2002:a92:dac7:0:b0:331:3df2:bb3a with SMTP id o7-20020a92dac7000000b003313df2bb3amr490841ilq.2.1683040804804;
        Tue, 02 May 2023 08:20:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:907:0:b0:763:ade0:a7ad with SMTP id t7-20020a6b0907000000b00763ade0a7adls2663828ioi.3.-pod-prod-gmail;
 Tue, 02 May 2023 08:20:04 -0700 (PDT)
X-Received: by 2002:a6b:ee17:0:b0:763:5ab7:a8ec with SMTP id i23-20020a6bee17000000b007635ab7a8ecmr10315705ioh.12.1683040803987;
        Tue, 02 May 2023 08:20:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683040803; cv=none;
        d=google.com; s=arc-20160816;
        b=pBC4bnxy4IsTqc0xm0fl5zbRpUMBfjKcA+qWfDEXH3vkRG1mPkTT6cKcgd6kfpOzKO
         i3ujrgN/RhIwwSbz9B2IXHAtfCoe7S2m2k9KeiyQw4LWEdr7e7ltdWBdrrOWDzaiD5sz
         jUZDhJOJLIwfk+og4nSJhx0XaE1w9s/lJ8Sx0Ik0XAAdVWoBCAaXuEBbK+o1o6peKzFb
         TLv37SQsyqQShtXWoKl0ZSpSTX1LPOWZLfevfepZcmuf8Ckt5PS2mqXVJSWZ16gAX8so
         fwD+L1HNQcA1i8x85ii2CXy7BqIXjyb+1wiPNkU78N1tDsBM5I15Ofhb89P5XRyIlrdz
         eq4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=2UFtU6oUaOr0vAs1hqgYmpK0GvH9Lqd4XIp3l76+ytw=;
        b=HPZdIK+LLMdLX64notouFLXGLv91eX3tEulj2Gj+2IAamWupyycPF1wXU1acT9alZV
         kvllhncw2dnuhflt99I3rewy4wS8m7Cd0ulqWF5LBKDFoFqPZzVEAMYdnNZvqy/kuZXG
         T1SywL3zlnz/rTPl4bGdRww7ukM03/VcqE8AvDdiBM8wiTFnms1KT2MM/uG73Ytr/sSj
         FOeK2Te7q16BBII/qS2S6FH4XmgDVHlyO6df3+oOIC3AKZhWHAOA8idDWCqneDBcgGDb
         x/bTq4fn+Gt8tpINvf7uo0pJFGKQO9PBBN5IbNHK22X2YVJ0KqzXhUFeiDDRVP5796pd
         zusQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=fQDTcAPB;
       spf=pass (google.com: domain of andy.shevchenko@gmail.com designates 2607:f8b0:4864:20::f35 as permitted sender) smtp.mailfrom=andy.shevchenko@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qv1-xf35.google.com (mail-qv1-xf35.google.com. [2607:f8b0:4864:20::f35])
        by gmr-mx.google.com with ESMTPS id bb9-20020a056602380900b00760f0b7ff47si2307657iob.3.2023.05.02.08.20.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 May 2023 08:20:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of andy.shevchenko@gmail.com designates 2607:f8b0:4864:20::f35 as permitted sender) client-ip=2607:f8b0:4864:20::f35;
Received: by mail-qv1-xf35.google.com with SMTP id 6a1803df08f44-5ef41569a3fso18188426d6.3
        for <kasan-dev@googlegroups.com>; Tue, 02 May 2023 08:20:03 -0700 (PDT)
X-Received: by 2002:a05:6214:124a:b0:5f1:6892:7449 with SMTP id
 r10-20020a056214124a00b005f168927449mr5506301qvv.28.1683040803341; Tue, 02
 May 2023 08:20:03 -0700 (PDT)
MIME-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com> <20230501165450.15352-2-surenb@google.com>
 <ouuidemyregstrijempvhv357ggp4tgnv6cijhasnungsovokm@jkgvyuyw2fti>
 <ZFAUj+Q+hP7cWs4w@moria.home.lan> <b6b472b65b76e95bb4c7fc7eac1ee296fdbb64fd.camel@HansenPartnership.com>
 <ZFCA2FF+9MI8LI5i@moria.home.lan> <CAHp75VdK2bgU8P+-np7ScVWTEpLrz+muG-R15SXm=ETXnjaiZg@mail.gmail.com>
 <ZFCsAZFMhPWIQIpk@moria.home.lan>
In-Reply-To: <ZFCsAZFMhPWIQIpk@moria.home.lan>
From: Andy Shevchenko <andy.shevchenko@gmail.com>
Date: Tue, 2 May 2023 18:19:27 +0300
Message-ID: <CAHp75VdvRshCthpFOjtmajVgCS_8YoJBGbLVukPwU+t79Jgmww@mail.gmail.com>
Subject: Re: [PATCH 01/40] lib/string_helpers: Drop space in string_get_size's output
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: James Bottomley <James.Bottomley@hansenpartnership.com>, 
	Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org, mhocko@suse.com, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net, 
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	ldufour@linux.ibm.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org, Andy Shevchenko <andy@kernel.org>, 
	Michael Ellerman <mpe@ellerman.id.au>, Benjamin Herrenschmidt <benh@kernel.crashing.org>, 
	Paul Mackerras <paulus@samba.org>, "Michael S. Tsirkin" <mst@redhat.com>, Jason Wang <jasowang@redhat.com>, 
	=?UTF-8?B?Tm9yYWxmIFRyw6/Cv8K9bm5lcw==?= <noralf@tronnes.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andy.shevchenko@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=fQDTcAPB;       spf=pass
 (google.com: domain of andy.shevchenko@gmail.com designates
 2607:f8b0:4864:20::f35 as permitted sender) smtp.mailfrom=andy.shevchenko@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Tue, May 2, 2023 at 9:22=E2=80=AFAM Kent Overstreet
<kent.overstreet@linux.dev> wrote:
> On Tue, May 02, 2023 at 08:33:57AM +0300, Andy Shevchenko wrote:
> > Actually instead of producing zillions of variants, do a %p extension
> > to the printf() and that's it. We have, for example, %pt with T and
> > with space to follow users that want one or the other variant. Same
> > can be done with string_get_size().
>
> God no.

Any elaboration what's wrong with that?

God no for zillion APIs for almost the same. Today you want space,
tomorrow some other (special) delimiter.

--=20
With Best Regards,
Andy Shevchenko

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAHp75VdvRshCthpFOjtmajVgCS_8YoJBGbLVukPwU%2Bt79Jgmww%40mail.gmai=
l.com.
