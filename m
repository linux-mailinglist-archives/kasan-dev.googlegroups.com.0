Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5PSZCNAMGQE64ED7TY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id BA055606FEB
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Oct 2022 08:17:27 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id h19-20020a63e153000000b00434dfee8dbasf914272pgk.18
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Oct 2022 23:17:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666333046; cv=pass;
        d=google.com; s=arc-20160816;
        b=y2lBtK6MRnZSkHhWv8Vs9g1xmN2q+RTivT75S4dyZHKxTxIJfkh8DTMhDxxbmfJyCf
         x/2OELWpjBMDeH8TrQIpqqlUi1dvM5MHrbDmILt/KZPG6vxJhCncyU20jUU4Rzeaql7g
         YGW7ibQcntNndBnsSPF4+C49VLbL+ULVAPip2STriAx2tEjF+stK/ZOTJ/0Pff11CT2N
         6Not4RoiGXdY/XMmoDplTckIi6f1Tc3qVEUse/1QoykC4v3HkxveJTO98lDdc0ZNbsbH
         MimaIh+KlqoYlu/CyusiXRDOFrp68aQwPA0EYLBtJ7/9XyOMvVFN/pcmldVc8mS7ReYk
         Pvvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=acijktt2C6st6CVfgMLa7JHzJmgdZknWMdge7UX41ac=;
        b=pCZyXYsfTOOVSWP7IFcPmucHchbupAzWmBwyp3tUBPx++sIGc7JAwn3o2+giYdueX2
         xdZUcFTnsX+ZwIunTiLjlxAaIu6qiiElKsXo4INKsAiPzCygNYTkqPzRDXiyR7Kx+d8J
         8sB/z01SQfbME75o0KK/xDChBu7YoVictF12fD7XZTtMDNVdbmpmoiD2APVs1EphU8yE
         tvAR+z6IqqA0mZDGkMKK7TqRPkX/94XkEhuk+lz4GBiCkzmhTwt+/nGchIo0m24d4/R3
         2R6tAySSrrRyjpyegjcGN241kqjUnDx2h/J6mAZICMwBMax1JRxjINmQWpJwD/p4nbUF
         jG8Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=SkzcDLX4;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=acijktt2C6st6CVfgMLa7JHzJmgdZknWMdge7UX41ac=;
        b=IKJTDCtvvTT8GCJyBf5x+stdsxeGoWvc+RQ8GEcTCKYM4yHJincPF9/FXvLQc7TrsC
         YvuqbUgkT195pXjd6i/gpFAOL9uMqw66d8SbbZ/eLekcVOg7Mf0fN5i8mrf12sWGPZvn
         MdyiRRQEQi9QJpXGSP/78WcTR+XuAahHWoqrJ4gOh9ecdA67T+rhbmgYR20k/t3o9AhV
         7CWf5qOrqLLXmq3MQOWX5finTIdbMWtzbru9ej06iUY3s8pDaG5SMnm2rMfwwtDlPHvd
         wFyx821vARkGqzchH/nEzkJ1WEbjU59U7HNpBZ7lxqbRmFjTmoZbPNQjjGNQf6Mt/ueJ
         KN2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=acijktt2C6st6CVfgMLa7JHzJmgdZknWMdge7UX41ac=;
        b=U3p5ict98T2CcliDTbfcrjbkpSginenbAaX20jWYdpoEmTc+jAnb6NaLNhzd0zSA5W
         E+TqwdZHyKD6ZihNkdVdK8HMUm7gYws3TuUuma6orHpz5CvdFafKhuj+byrAFpTymVCS
         Pvk1jZUY+ZZjM7RXpqiImqgak52lvrCuW+cqg0qKKAuOMYo6qc3cq5lNaw2Ov6d0+BdF
         gtjS2QKa6PLwXnSw02XkQWBumpZ8iOSKRE92WdqwcLJxKSLO5zDXAJhUHj8sQdaVbt0d
         Pnexh/DgDCue3J0y8ERBvZzfhGB3OBfzMolCoVAyYm6huY+N3csgfhCL1Ax9nnPdFNL/
         +Gsw==
X-Gm-Message-State: ACrzQf1pk6qjWkvzKcxydKkuJCZrP8hxAsUHUUdpVq/zxJR2HwL8TJ8M
	42Io7BYgjXIViZYZtSD4egI=
X-Google-Smtp-Source: AMsMyM5txV/m82BFt0gCPRnOzVC0l8tcuqvoM3H6HbeuF5lXRWSRVTSzhGUiABPbhH2+UyvxzlB5Vg==
X-Received: by 2002:a63:2c8:0:b0:46e:9da9:8083 with SMTP id 191-20020a6302c8000000b0046e9da98083mr5480302pgc.186.1666333046049;
        Thu, 20 Oct 2022 23:17:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e904:b0:17a:6fa:2290 with SMTP id
 k4-20020a170902e90400b0017a06fa2290ls1348301pld.3.-pod-prod-gmail; Thu, 20
 Oct 2022 23:17:25 -0700 (PDT)
X-Received: by 2002:a17:902:ed82:b0:178:5653:ecfb with SMTP id e2-20020a170902ed8200b001785653ecfbmr17933390plj.58.1666333045020;
        Thu, 20 Oct 2022 23:17:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666333045; cv=none;
        d=google.com; s=arc-20160816;
        b=fNygiyR8d0aNVk8Ggxi3YL8LW36BUHXqe95geikED8UPE2z+dXZEx6Qfmuv/PVr7MS
         2s8U8twMo3gjvYiu/Qfr8HK+XN0vQBIJ/SMZbV2zhAUxhFMOk/oyrErdbMfvQI5VxwNd
         tDYnw42rTbBU80/QCX7F7aTKs8v8sRhFS3PMuyoAP8t3lJyLaBjTOj29rPApaZX025dM
         3fCYmYqJkpaFR4dGvJc9cQje+AzT9c1mJ61y+gv1vLOrBwlRwjQSjrySpSZJvZZkjy1H
         TAtzXt8JhARBneoYK1mfxNgmDx8JjdT9VQ8h/apFoX2KudJhmibU0Uu5PzRG+cnPgidX
         QpYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=zIf8ZNnAW78yhJlmbsbMxnLGL5lK8A9xrLkSuvVZ5vY=;
        b=zQ12EuLUyF3avezJjabu1qha9+eum4oD1tfQOTMDHzASlFvoOVxD5Wxe9m22D5PQCo
         Kw6sOqZt5lv7AQkZefAYCIHqKZy2wkNnOmg27Rm5dAtXGIXZpH1kFbMmjOu/576XlHHb
         n7sDmpWoPmMhH2Dl6E0/+ufzjCsh61phky5NJCn/l6YQOKBNix/YtZumt5rRn3G1JESg
         hDm3L3ii5PL/p0Nhnn51MYtXJhPSBShO6IH1HIA49GhC0j9zdDpK2CT6YgXkG/lCV4NY
         t506SJO1dtMmwpTT72YEHLlYFqS/If8z90PYqciyhie1nbjAtuLrEzE0HlfuFJz0PvX7
         DpDw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=SkzcDLX4;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112b.google.com (mail-yw1-x112b.google.com. [2607:f8b0:4864:20::112b])
        by gmr-mx.google.com with ESMTPS id nk19-20020a17090b195300b00212caf6f066si132288pjb.0.2022.10.20.23.17.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Oct 2022 23:17:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112b as permitted sender) client-ip=2607:f8b0:4864:20::112b;
Received: by mail-yw1-x112b.google.com with SMTP id 00721157ae682-36855db808fso14761127b3.4
        for <kasan-dev@googlegroups.com>; Thu, 20 Oct 2022 23:17:24 -0700 (PDT)
X-Received: by 2002:a81:1c07:0:b0:358:6e7d:5118 with SMTP id
 c7-20020a811c07000000b003586e7d5118mr16062156ywc.255.1666333044032; Thu, 20
 Oct 2022 23:17:24 -0700 (PDT)
MIME-Version: 1.0
References: <20220915150417.722975-19-glider@google.com> <20221019173620.10167-1-youling257@gmail.com>
 <CAOzgRda_CToTVicwxx86E7YcuhDTcayJR=iQtWQ3jECLLhHzcg@mail.gmail.com>
 <CANpmjNMPKokoJVFr9==-0-+O1ypXmaZnQT3hs4Ys0Y4+o86OVA@mail.gmail.com>
 <CAOzgRdbbVWTWR0r4y8u5nLUeANA7bU-o5JxGCHQ3r7Ht+TCg1Q@mail.gmail.com>
 <Y1BXQlu+JOoJi6Yk@elver.google.com> <CAOzgRdY6KSxDMRJ+q2BWHs4hRQc5y-PZ2NYG++-AMcUrO8YOgA@mail.gmail.com>
 <Y1Bt+Ia93mVV/lT3@elver.google.com> <CAG_fn=WLRN=C1rKrpq4=d=AO9dBaGxoa6YsG7+KrqAck5Bty0Q@mail.gmail.com>
 <CAOzgRdb+W3_FuOB+P_HkeinDiJdgpQSsXMC4GArOSixL9K5avg@mail.gmail.com>
In-Reply-To: <CAOzgRdb+W3_FuOB+P_HkeinDiJdgpQSsXMC4GArOSixL9K5avg@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 20 Oct 2022 23:16:47 -0700
Message-ID: <CANpmjNMUCsRm9qmi5eydHUHP2f5Y+Bt_thA97j8ZrEa5PN3sQg@mail.gmail.com>
Subject: Re: [PATCH v7 18/43] instrumented.h: add KMSAN support
To: youling 257 <youling257@gmail.com>
Cc: Alexander Potapenko <glider@google.com>, Alexander Viro <viro@zeniv.linux.org.uk>, 
	Alexei Starovoitov <ast@kernel.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Biggers <ebiggers@kernel.org>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=SkzcDLX4;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112b as
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

On Thu, 20 Oct 2022 at 22:55, youling 257 <youling257@gmail.com> wrote:
>
> How to use perf tool?

The simplest would be to try just "perf top" - and see which kernel
functions consume most CPU cycles. I would suggest you compare both
kernels, and see if you can spot a function which uses more cycles% in
the problematic kernel.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMUCsRm9qmi5eydHUHP2f5Y%2BBt_thA97j8ZrEa5PN3sQg%40mail.gmail.com.
