Return-Path: <kasan-dev+bncBCSL7B6LWYHBBUX4ZKRAMGQEOCYMS3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 63BBC6F5FA2
	for <lists+kasan-dev@lfdr.de>; Wed,  3 May 2023 22:04:35 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id ffacd0b85a97d-2ff4bc7a770sf3275118f8f.3
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 13:04:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683144275; cv=pass;
        d=google.com; s=arc-20160816;
        b=byjJuHO6hpk6MTCCC7TPLxtZcIXLkHBEOmEtNFbzVJefFi5F4xvL10hhilGR3Af2pn
         m9fTWahM4LIyh6INhi0s6vWJ23LVAtu3i/lLdc0s0hcvVsz4TwxrJyA07AjfvIJIRgYr
         +JL5aRDSVXPvp1CQANaECQQ7/6No7WdeuRZztJSH5jKMwK4hsdmMOowtM/FwHuLb7M0D
         /Q3sdZcJABWjxf2nVrx7GkZ8Som83VdXPb4vLcGZUxoBby8qlEYtcyklyQ8z7GkdG0BV
         uAj24bObzwRgxQCMv2nQgsORPjNWoByEwxWyOV27gNjIYWKxP1d1/vCqq6YMzRwVXqRy
         p+8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=CSl5Htvxq2plfOcV8EcJLew0vuXhTR8Bwr+12ekI6g4=;
        b=afIMG/PixzNY+OJi/o05TcfCYkJ8+IoqqNJ4KXd7k7NNahpJNGBivoXGN+y+cGQHKF
         Qdm6lxsHx0sJmHQYrqrMxpjA87jAHidNaHZgqFL0gJusvwNQWJ+VEBd4EKyX9k/I8UKy
         KQVD5Ba1r4wsZJ6c1ABohACgRnHTa7+QepB+0YOkXFJFsjJKvWOfoa8z0iXJaiPd4kmr
         NQWA1LckXJgm1llEPdAR3aKBn/Rp7Jma1TkUd/U4GQsuBn3t/8nnZ0BmOJDfO7RlnzNH
         Rbrg2xgvPJQ4mYaLbT5ldjrxFO6s9fIVtJWFpqTIw20LlfrudV67VNNsHXjZj5EuIb/i
         fsHA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=X9cvzf7Q;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683144275; x=1685736275;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=CSl5Htvxq2plfOcV8EcJLew0vuXhTR8Bwr+12ekI6g4=;
        b=Owx2bOJBRmYYdUXDt4aKzvGKp7PhwCcktuulPzyVHJeD9RbrXcKH81sdVnasUA3u1m
         ewzP7orYO3pd36VkzEbCOR6eVYjs6OTo3/vp3fK104UOmKVntPiHRVQtIBJq4vbPuFDh
         J2k6FvWCo625BZ+dQgKdDLispxX+XYcL7xS118T6Dn7vA3q/KenP+/gaSfZOHdl7x+NI
         UdDe2+ts26XSlsJZgvHqA+y+DEOlbScMmJnX2yUbyYQPR6tlErIbO/yFNGPJtJnfLih0
         FeDEFzah8uqRmKOlshC5O+rVqxZhbtzBalXMqm9xBG3NeWGdmwX9ecD+9YyuoN1TO1S8
         0kSw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1683144275; x=1685736275;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=CSl5Htvxq2plfOcV8EcJLew0vuXhTR8Bwr+12ekI6g4=;
        b=QYvMHSSwrvvpbgfe4x7NHmipp93OnhoyWXBh0PmrEj9pb3xwJYYMxaHTs/v7UoWq8d
         InieQwRq/fB/xodjp2glw40jWGBGv0ceMzdd9oibNfNgj2qV8TnjnslxSArRvlooNnAc
         CZSEJf/k45wzBeFujrWLoZXk/VJ/SUE0DFrsTN/XWJ3geG6ab8EfnbfdItuJzLK4QeB5
         kN8nfSeprF4aTPhwqY0RAnQeeydpVn6GKN1QZ62dKwH90xeXsrRNkR1FCdYD1DNYKqrA
         QiPzoVhG5fJ2Ls7sNRA5nGkvAgHgXD7B90j3+CBQnkN0MhlL6iXRY4E/xA6HUpTh6eJP
         WFaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683144275; x=1685736275;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=CSl5Htvxq2plfOcV8EcJLew0vuXhTR8Bwr+12ekI6g4=;
        b=KyzME3cnH4ExTuhvgeAGjI2ADAjf+rBTAJdqL7c2MTTO6Rdqfx+FGnq6SRNvIMEwjo
         u5tNODZMLsF90C+Ln1YG9sBIlOuMeNbp+sKDBDIdKwC9RTGp2auQVYVVXCWQ91JbPNHW
         /ZuoNkJMnYxQ6p3twouZ2ymUMuD7a+yscjOrraf3UUEAgZLgZZUjp2PGuvkSQhyfnTzR
         jJ+9uYRXSbVh3EAxPSHWfxZpaCp6ZPnDerpBZhqVgt4okOBOKj4fCi+0mqu1oEQGrkuK
         1CRkmMyQUSh4N0IC6at7P3Yoq2oQbakHuOK1Nzq3S5zpgqrGAGy4xXlmtQmV9lmqWP4I
         LneQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDwp2mLdvJlDwj7C1b2QvVesHuTiF39Oba10lUhS+QpAzRpvCfeQ
	k/fsZ8OQO7ns7JDksTKK67I=
X-Google-Smtp-Source: ACHHUZ4vaETmJm7jiuiQ8r+Jb9lk7E7f4/7cX7lkwVXDNNc/MQaoxt0Vl20IQXuG4LswvBeD0YrHlw==
X-Received: by 2002:adf:f2d2:0:b0:304:2af2:1139 with SMTP id d18-20020adff2d2000000b003042af21139mr156746wrp.10.1683144274829;
        Wed, 03 May 2023 13:04:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5c0c:0:b0:2f4:1b04:ed8f with SMTP id cc12-20020a5d5c0c000000b002f41b04ed8fls1377761wrb.1.-pod-prod-gmail;
 Wed, 03 May 2023 13:04:33 -0700 (PDT)
X-Received: by 2002:adf:e904:0:b0:306:4063:1afe with SMTP id f4-20020adfe904000000b0030640631afemr694352wrm.71.1683144273009;
        Wed, 03 May 2023 13:04:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683144272; cv=none;
        d=google.com; s=arc-20160816;
        b=iJReUAmYK1O+CiwEh0H8lT9bJEcaEVZTTXzMbYuBz8Jrzr4dG438MprIKjpGZuDnYP
         x6XvYZO8EAuOFMSNYBVgonKz4qmw7Gb0/aFtNCa0nI0KAbihJABTiBMmzQsa7mwnBwZU
         2Yr2ACDRsehxmri+OWhkY2iDzObRsQXMJgGTqvjs98rg4sSXaZd9NTD2T6PjkgbdGZxY
         kT5TkRUXAOpBgn3Ssm2b/2NFOCm1mPLlTs6IH0PCOhC0XR3EMSFL8suud6kElwXh2yYV
         q++2JerITMoJw6rX3/Bxxl1R5TFC0rVntmchv1FoKj5aG3Ce+5FoK6xsimhwl8bb6len
         7guA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=rHU5powRCH79ePrW9PLsNOR73hzLy7pF/AR2cVrEP7A=;
        b=V+dteDr1C11ZUy0QzyqzikgdZiaDKv/QrGSQtNIBSre5lp+iLETdwCGHoKTf78VnbF
         Io3fDn1Y9a4CThqIAbsL1XWVkNtrJTQNvBktZm3cFcKvLrUrILi9Ksnaf0xW3wubrX7/
         eG10NjlmMth1znzzFX7m/YNtMorSqalvb1YEqEkiALk5ZCi876w9fX/1qMDSl92a3YjV
         F8ewhnt1Dcg21PzNhmjp4ZEqgX6Bf3tLeRAwhQabIHBophOra/kHxgSzSxbj0anNKLh5
         Mx/sw6Q3VKp7LOwz2mwbx7PhboKYY8go8rwBGKy4E4P5no2qkJKUkai/mabRwyiW4Lhi
         MO7w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=X9cvzf7Q;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wm1-x334.google.com (mail-wm1-x334.google.com. [2a00:1450:4864:20::334])
        by gmr-mx.google.com with ESMTPS id v8-20020a5d59c8000000b003063a286483si292351wry.0.2023.05.03.13.04.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 May 2023 13:04:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::334 as permitted sender) client-ip=2a00:1450:4864:20::334;
Received: by mail-wm1-x334.google.com with SMTP id 5b1f17b1804b1-3f178da219bso55336025e9.1
        for <kasan-dev@googlegroups.com>; Wed, 03 May 2023 13:04:32 -0700 (PDT)
X-Received: by 2002:a5d:5222:0:b0:2fa:27ef:93d7 with SMTP id
 i2-20020a5d5222000000b002fa27ef93d7mr907489wra.42.1683144272448; Wed, 03 May
 2023 13:04:32 -0700 (PDT)
MIME-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com> <ZFIMaflxeHS3uR/A@dhcp22.suse.cz>
 <ZFIOfb6/jHwLqg6M@moria.home.lan> <ZFISlX+mSx4QJDK6@dhcp22.suse.cz>
 <ZFIVtB8JyKk0ddA5@moria.home.lan> <ZFKNZZwC8EUbOLMv@slm.duckdns.org>
In-Reply-To: <ZFKNZZwC8EUbOLMv@slm.duckdns.org>
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Date: Wed, 3 May 2023 22:04:21 +0200
Message-ID: <CAPAsAGxcCJai6PpTVOkqAB-vG+Q71hb1exsK79hJ7Kb2eKAtjA@mail.gmail.com>
Subject: Re: [PATCH 00/40] Memory allocation profiling
To: Tejun Heo <tj@kernel.org>
Cc: Kent Overstreet <kent.overstreet@linux.dev>, Michal Hocko <mhocko@suse.com>, 
	Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, ldufour@linux.ibm.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, muchun.song@linux.dev, rppt@kernel.org, 
	paulmck@kernel.org, pasha.tatashin@soleen.com, yosryahmed@google.com, 
	yuzhao@google.com, dhowells@redhat.com, hughd@google.com, 
	andreyknvl@gmail.com, keescook@chromium.org, ndesaulniers@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	iommu@lists.linux.dev, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=X9cvzf7Q;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::334
 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;       dmarc=pass
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

On Wed, May 3, 2023 at 6:35=E2=80=AFPM Tejun Heo <tj@kernel.org> wrote:
>
> Hello, Kent.
>
> On Wed, May 03, 2023 at 04:05:08AM -0400, Kent Overstreet wrote:
> > No, we're still waiting on the tracing people to _demonstrate_, not
> > claim, that this is at all possible in a comparable way with tracing.
>
> So, we (meta) happen to do stuff like this all the time in the fleet to h=
unt
> down tricky persistent problems like memory leaks, ref leaks, what-have-y=
ou.
> In recent kernels, with kprobe and BPF, our ability to debug these sorts =
of
> problems has improved a great deal. Below, I'm attaching a bcc script I u=
sed
> to hunt down, IIRC, a double vfree. It's not exactly for a leak but leaks
> can follow the same pattern.
>

For leaks there is example bcc
https://github.com/iovisor/bcc/blob/master/tools/memleak.py

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAPAsAGxcCJai6PpTVOkqAB-vG%2BQ71hb1exsK79hJ7Kb2eKAtjA%40mail.gmai=
l.com.
