Return-Path: <kasan-dev+bncBCUY5FXDWACRBS5JTPFQMGQENSLUZRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 55C56D1BB6E
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Jan 2026 00:27:09 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-59b6cbd5493sf5641731e87.0
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 15:27:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768346828; cv=pass;
        d=google.com; s=arc-20240605;
        b=HqjYUJ2etzE8ZOC/tXcdHiPC1ndNXBmROHoNYTTqr+jgsUognm+nSuoc53V39hzOwL
         V39pLPRc7se8s6R5zr+pOeYnuEPTVIIX33JUGj6yZlFMVZK6NFJ0gWd8cJpUbJ6D8y6O
         MFqlyqWU022JrCPZZwcTqxSmpeWq9M243vwyLisQrju88i/uugQmmrzTcX/DWDBgMtmg
         WEt4FOJqQyeIzPAbPtVlaTDByQMrUqBYxmGc+UqVgj5298fK98J6P38FTK6RetVaKQpd
         pielW01Z8jobNuWpQF+t+fgazxZanQtRkv3cv/Aa2sseBnsqc6xzv7klANJyK9F49bKn
         P0IQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=DfFDPWMwJTYTJZ9hmgk3UeCugjcz8AiHWBQWM7258F8=;
        fh=n5hJhXF3wU2jEG9E/bqekSt2gh3ZgMPKDhkEEma2p8E=;
        b=gL5/fUscEmna8Fw5OoDF8j8HO85JeQSNS4oTb43e0MXUCAtCG6a1FqdjOU5/FMSkxt
         Y9szi53x6o1mrEFGrkN6tNtWfDW5XnHcKl/Ag8IXnrPWmhWQo2OiQSO5yN4TONEWok0o
         YQQ6bEaHll9Cl/2E2K95KYtXQdZ9Two0fOsgOLE3JBtKxitscvoiSjeZC6XHS501DXGE
         2Ube3FpGd9xZWFz77iDVYcc/ntYxXVYz6Vx8ZexEH6N1tql686H7YStuLY1bbWhylQ2u
         3AXGTNMpwjBJrUqv/NciGkryj5YxCMUya928XZD/3dVsjD2CfIXMXsa98Brt4B52Z0IU
         K1DA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Jo6BVKzH;
       spf=pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768346828; x=1768951628; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=DfFDPWMwJTYTJZ9hmgk3UeCugjcz8AiHWBQWM7258F8=;
        b=Ploxi3VMMGPj3GPEozjXazj8Yb1NAs7mcuFzdqH9L8MiIhjh2kOS8FgGPoih8eJXrn
         lcdfUsa5VQRVMLfPsjjzzn/bFrnkZbnCVQzp99hxFInztKlO+XK2Fe7eyn+q+zj84kG5
         JwpcO6Yr9wbwbcjeppjxJJ3WNQf/lTGbdib0PSMY1drGAIhx5tlymrC/0FO0it0hnPhT
         c4PZR3tEameDxYQxTiGSySufR97g1l22HdJ5QP7vzC8YPMo6n4QHl/U/Z/dInzfymvJ5
         rY7RDJY1XLfdqcmQV5WIr7RCkkwy80V4PkbyMqZ+8Pcke6TUoNsOE2RfWEfHIsssAIwa
         yQeQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1768346828; x=1768951628; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=DfFDPWMwJTYTJZ9hmgk3UeCugjcz8AiHWBQWM7258F8=;
        b=ZgcIQveAWpfywYXeEhcIFT+uu8WcuJ3c/ExfJbZfBjD1LPyofqRUkFUGVgzsO2OFeg
         PaEKpmgG49SbmTFvckO+zFe+m5s0GIXtLc3VIfpUW0yXYL+4d5PjeIcthDVDo8LTI7GH
         NiiGT9PRjpHLeIhI960hkNBPqXm6SqwTVE5ObOMqj+1y3JpTdgGqMy+pwOlPpF3sP5LT
         lvq2J22luUVItHZtCfe4GLwLHZ7nLd7oTsO7aH0uSecWN0pKHTN5frrCQgJ65dbwJYGe
         5/fC0PAVsVzB16n/lbR81Bo5ERJzllLcsni29w+tRXtyFHhtj6m/LWr0DRkrt4ZFVj4m
         psuQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768346828; x=1768951628;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DfFDPWMwJTYTJZ9hmgk3UeCugjcz8AiHWBQWM7258F8=;
        b=WdEN+Aj3FAGOgj5nVU4A4w9nNj1a3D9Q89jQ8CX8lH/95+aOU4VkJE8IdvPNs94JLx
         pSIe297552nTXstQj9rYDwKZyp83uUYFXQb/S232JLJ2vFGXr4vZp+GUCXEd3PTOcSVW
         Uc+WoinI7peymr1RmXes8DrMi4p1vGALH9wsEKap8DYjkTxAgEX2YGXrtMMhb+IV335Q
         BrYo/o6IIdvY52PzxOYF7KV/3HOstm9wFZLgLdiXuyOExlNY+o6ueyfcSZOz5CmNs3Pi
         xb0d3nRTQCpoPvKXcQmYyGKBvX078XX+cBiXuNAv+YT+oOkCxZEGaMEP9OHOk3ino3De
         yMWg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWsRN8Os9KUmWzRb0dhQzR3JzwRJigWO278VZ1MX1hAssu99O7eWBx5cLsoTekGHOhfgxojnQ==@lfdr.de
X-Gm-Message-State: AOJu0YynRGk22lTSNv0Pt2L7iiGQCgUkY7c1RPt1rtlZmi/4/AZ8B/bp
	8+Jv98SirrV8EBd2bDumxkD8NGJuWfdXlG7p/YsKy9P4BthggvUiFjYH
X-Received: by 2002:a05:6512:3b8e:b0:59b:6d23:43bd with SMTP id 2adb3069b0e04-59ba0f62721mr161243e87.15.1768346828320;
        Tue, 13 Jan 2026 15:27:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EtEJslrkUWvSh5FlkM9M68dl4wmhmgFJz2Xn/JG1HPvA=="
Received: by 2002:a05:6512:23a3:b0:59b:6d6d:c with SMTP id 2adb3069b0e04-59b6d6d0095ls1387708e87.2.-pod-prod-09-eu;
 Tue, 13 Jan 2026 15:27:05 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVQaioCzdCH/G1OhcGw5yw0fed5taaNCur3TReNFR1c1BrK3t4H+h86AYVCdeE4HBYqNObEbSkA2vc=@googlegroups.com
X-Received: by 2002:a05:6512:12ca:b0:59b:685b:b3cf with SMTP id 2adb3069b0e04-59ba0f5e464mr189566e87.5.1768346824980;
        Tue, 13 Jan 2026 15:27:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768346824; cv=none;
        d=google.com; s=arc-20240605;
        b=XlfMclxEHvtU2MSiezhRiMYpFW7qKcgULfzI6k11mQYDDc8OwPKPr6Hf8niCR1hXmv
         bFpNijXb/l9wtPdxias1JvjHG0mOZuEReSOP0B9lggtbl5tKyvRBvzzHwh5Z9VmstS0k
         MWq+FJY7f2fLn0/gzx31UJTEcg8XUXGqXMoG7uyyIunNMrCsK02C3zRZkcUxsYtXuR4B
         IUQzMP6IwjYnt7i55OXHCp+RaQWq697ciRbABDGmc8adOWA+yzf6x/jmAjyOKwmePrl9
         N4/G8P6q9xKxYJq0/Vs13simxtSN8LCn9uHdn/sMrQJxiQJtYvcV1uopadIJMuT7atjr
         AGCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=XIxHGmAm1SZZrcYdW9mVCY8ENSWv9Idzn4C9R7aSfY4=;
        fh=UoYoeuMemy8p9shUs2k9USos8VZNf4zB6yA2no/MW0A=;
        b=P6yL8c5w4Ok++MnPhVxAfyXNTTlfC8BbJAwEUCUXN70bAhkPTkkRgOezws+G2QtvHb
         +lJI4J6eJrfJLe3BJ/g477Y95lBXWfKaAKglK9sNsZ4Z+I/Me8OAygiacih8WLx6cs6W
         jZ2EekvhvCdYP6t2O4hwj1fPQ1gE+W2eKZbgv1tQc0c367qCfqDCPy76RJa5HM5n5CDI
         BxqbMa8MRSDVqfXOzkXnMrJlVm2AXOmTRvlxwQRowbC+2xB9i7/blOuHLYrm9y6MjxNJ
         b0QarcOy5jkExuNj303NcwSaf6HCKxivwKXFnbLt332ro4bVh51FMAip5IlFW0ZAVCz6
         9+zw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Jo6BVKzH;
       spf=pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x435.google.com (mail-wr1-x435.google.com. [2a00:1450:4864:20::435])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-382fc3b94f2si3449741fa.7.2026.01.13.15.27.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 13 Jan 2026 15:27:04 -0800 (PST)
Received-SPF: pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::435 as permitted sender) client-ip=2a00:1450:4864:20::435;
Received: by mail-wr1-x435.google.com with SMTP id ffacd0b85a97d-430fbb6012bso6495429f8f.1
        for <kasan-dev@googlegroups.com>; Tue, 13 Jan 2026 15:27:04 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXOp5GXgiec5oxWXROTyxFME01UCfR+aPUcF1jcZyX2M83BuayvL27ydryUhgUnRb6IivUWu0AVzpA=@googlegroups.com
X-Gm-Gg: AY/fxX40rYPv0pp+WBWwkzujMvz/cAfCgp0PbtlPcRCUzaVIiMYs1jhRb2P6/KAJLyD
	wOKzxRXEd2LCyIbIsWzL4EJ6aVTErPs09MJBEC1RhUWIWxgGnidLjppe5HRcI52oE+mV/lqTyCU
	3djnmNOtfWbx5tTl40OUZYRdN2zI9OGJQxpDknwHtHeflvZYat+JWA2oarkLVsDrfnyBs2240KN
	oZWmrY249+QwxtoxCEm/iRPICmZSvgVSn8Fm96eno4pfKpER1sqKSEQstmaY0vzbSQs/gp63ZHe
	wl3wNZXhb0qHYOL9lY5io1RBmRSZ
X-Received: by 2002:a5d:64c5:0:b0:430:fd0f:2910 with SMTP id
 ffacd0b85a97d-4342c501a57mr685880f8f.26.1768346824132; Tue, 13 Jan 2026
 15:27:04 -0800 (PST)
MIME-Version: 1.0
References: <20260112-sheaves-for-all-v2-0-98225cfb50cf@suse.cz>
 <20260112-sheaves-for-all-v2-6-98225cfb50cf@suse.cz> <20260113183604.ykHFYvV2@linutronix.de>
In-Reply-To: <20260113183604.ykHFYvV2@linutronix.de>
From: Alexei Starovoitov <alexei.starovoitov@gmail.com>
Date: Tue, 13 Jan 2026 15:26:53 -0800
X-Gm-Features: AZwV_Qg0xd2SuSeZtzkfObEmnG4DkzskoYODoJFcrxj4bx-h7Wvm-bafCffVqCQ
Message-ID: <CAADnVQK0Y2ha--EndLUfk_7n8na9CfnTpvqPMYbH07+MTJ9UpA@mail.gmail.com>
Subject: Re: [PATCH RFC v2 06/20] slab: make percpu sheaves compatible with kmalloc_nolock()/kfree_nolock()
To: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: Vlastimil Babka <vbabka@suse.cz>, Harry Yoo <harry.yoo@oracle.com>, 
	Petr Tesarik <ptesarik@suse.com>, Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Hao Li <hao.li@linux.dev>, 
	Andrew Morton <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>, 
	"Liam R. Howlett" <Liam.Howlett@oracle.com>, Suren Baghdasaryan <surenb@google.com>, 
	Alexei Starovoitov <ast@kernel.org>, linux-mm <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	linux-rt-devel@lists.linux.dev, bpf <bpf@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alexei.starovoitov@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Jo6BVKzH;       spf=pass
 (google.com: domain of alexei.starovoitov@gmail.com designates
 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

On Tue, Jan 13, 2026 at 10:36=E2=80=AFAM Sebastian Andrzej Siewior
<bigeasy@linutronix.de> wrote:
>
> On 2026-01-12 16:17:00 [+0100], Vlastimil Babka wrote:
> > --- a/mm/slub.c
> > +++ b/mm/slub.c
> > @@ -5727,6 +5742,12 @@ void *kmalloc_nolock_noprof(size_t size, gfp_t g=
fp_flags, int node)
> >                */
> >               return NULL;
> >
> > +     ret =3D alloc_from_pcs(s, alloc_gfp, node);
> > +     if (ret)
> > +             goto success;
>
> I'm sorry if I am slow but this actually should actually allow
> kmalloc_nolock() allocations on PREEMPT_RT from atomic context. I am
> mentioning this because of the patch which removes the nmi+hardirq
> condtion (https://lore.kernel.org/all/20260113150639.48407-1-swarajgaikwa=
d1925@gmail.com)

Right. With sheaves kmalloc_nolock() on RT will be more reliable.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AADnVQK0Y2ha--EndLUfk_7n8na9CfnTpvqPMYbH07%2BMTJ9UpA%40mail.gmail.com.
