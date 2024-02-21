Return-Path: <kasan-dev+bncBCC2HSMW4ECBBEGO3GXAMGQEIU7DVQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id DB7CA85E99B
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 22:11:45 +0100 (CET)
Received: by mail-pj1-x1038.google.com with SMTP id 98e67ed59e1d1-29976f92420sf146585a91.0
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 13:11:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708549904; cv=pass;
        d=google.com; s=arc-20160816;
        b=JYk+Gn09BzEmv+y7rsCa+BHtKGC5R3d+Z2doKLDfRIOws8npn0BtDD+2Tg0UVEcX+y
         55r7TAvGOR76ucom3bQTCsbgJzgODiWNyREx9QGPMWokE1RfxYVTCs8/1Hcg8pCy8itb
         /SCvfIRKUd81d7mjD6BKcYy/nTln3EuVqkbV7OY7ehkMIfQXG48gHI5+YAAGug2bZPt5
         18CgbQTyyTyh/c9E54od2TcXK/pn4x8kiOlp2GoUq1wWPiSyS4WcQMukzSnwlSROO5kE
         hm/DqEgWbaqqwtegMYreWV9hwCx7K7migrdJihBEdtvwzY6f0vbGshj6XFjmWX3xuGpd
         dfCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=T4PoXUuANdtkeysGK51o4BB+wGrx3kZcqhYMl4ucXEE=;
        fh=/pVULU6+LCAK77SGNw+B7lgbwABrqqUrhTit334tW6Y=;
        b=HoVYIcbXU0n/Y5X1hrWWusEfVODMdgAHetLNenARyoYvsRSwRMD8NP73Fo1S7q+MSz
         jybzbNXbND+jdRuYZ9OyePPr+OCweESilcLd3v3F4PnCETe0Ru9NPMAI5N+LS+vAbkfM
         rpkBAtCZn6fyupzwfAr50me6tKfyNa+Zl+75eB954nV+k0lCqsHRAtaGhpCI+ISvkBia
         Lmopjxk4sFmT30yr4gJi/k1jqt2xvDCQ8V3BP2YT91etu4KLA1VpV3UcC19IpzxbDrLq
         734lqSUsVCV+R0wrfHCAL+OBKtKVEUMeojOFUS2luTl7R9ZfM2Q+PCbXdRLX6lyPzCcI
         47rg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@soleen-com.20230601.gappssmtp.com header.s=20230601 header.b=jbiyEOFl;
       spf=pass (google.com: domain of pasha.tatashin@soleen.com designates 2607:f8b0:4864:20::829 as permitted sender) smtp.mailfrom=pasha.tatashin@soleen.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=soleen.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708549904; x=1709154704; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=T4PoXUuANdtkeysGK51o4BB+wGrx3kZcqhYMl4ucXEE=;
        b=FWJ3GBeY5enCP53A1r7B3i1HFFW7XtAXln6B+nHuzsiey78zCwNEZZTTn9XGnNUQuN
         +WkaZoy540C4qAyAfi3V9ujA1fT2L4SaUqXVYqthmUgrRXSmkGOkq3Wo1Kngylz6KGa+
         YggAwJQ8p3sRWTgo0rGcFpS4rSm7KQqT9KBSKAAD1307815oMxmZcE6kqo8ZFOw86+PX
         oJcsyDdDg78dGtRM+Ql2pzY7T9i6nk23VNa35wbR9a2UFluMm/TdVIAmgZDOHRQxhL8y
         xxX6p0f3QCx8CVOqkLkWGXdzpy1wlrbVr2khc2CYvRWMUhhNtoGZLcIS0mj48UOvo7Lr
         3WyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708549904; x=1709154704;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=T4PoXUuANdtkeysGK51o4BB+wGrx3kZcqhYMl4ucXEE=;
        b=MgayrN6CqgWfthGMK31psBPWCvH8kbd+Fe7UyNfPnraDvZ5lH45BEuC90EW87h30qM
         +oz0rDxkKmD/du7ejj4ioZ3iR1otowwmlb4RWpECpW6gGR6ux69ybWil1WHE8EIgrvCZ
         gbB5Ayq2a1cHMFLBYpuBq5m/EgNeHhW2r9mPObS+yjuC/jXOjDrnoDTS7TZaKrNVIvhY
         He7dg6qc4otVN4l2O1IrsJx57RMxOigRoDPfHe2kUUBKAR0d9Bfvc/du7DD80t7834RS
         xcd20Yl58Ax0MB6u5lqE4XOwDJ6AbeBp5HrJb03efOO0jqfqA+2L0O7doKzXaJR7mre5
         dSXA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWPdoCOTCfWvFwCAwfzexE5kCLtJdPrQrT9obZS2wV4Jdch63CbaQLDSyeF7JfEOGyml9TTP+EeqigXb9vLuY3Kl5k5ORSmqw==
X-Gm-Message-State: AOJu0YwEzAGggTWirbJUZ1/1LeXzgWbgVL15bqNhaPQ5EUBKbL7HnJlb
	not2nEco9QxXyLuTT1poXvpVCiR8QTOGCnm4un5yHjahcc0tczbl
X-Google-Smtp-Source: AGHT+IEadPkTn6yLhbak7zJ2CorBAZys20fwurby+vX7lLFrJcAb+F6Hj+capEwMc+PoONl+jrLgpw==
X-Received: by 2002:a17:90a:c57:b0:296:530:996e with SMTP id u23-20020a17090a0c5700b002960530996emr881668pje.20.1708549904192;
        Wed, 21 Feb 2024 13:11:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:380e:b0:299:3e91:b051 with SMTP id
 mq14-20020a17090b380e00b002993e91b051ls88532pjb.2.-pod-prod-00-us-canary;
 Wed, 21 Feb 2024 13:11:43 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUP+HQyeTpXtq67QX03pSb1JPOesSwvygaegPRWi4sUN5fJLO5xIRpXX4qfXjeY5IcynxP15ycpes8hyGhWzunRqKLmT+8JOfjNNA==
X-Received: by 2002:a17:903:605:b0:1db:c649:cff0 with SMTP id kg5-20020a170903060500b001dbc649cff0mr831402plb.25.1708549902731;
        Wed, 21 Feb 2024 13:11:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708549902; cv=none;
        d=google.com; s=arc-20160816;
        b=MFvjNDAV4aMf9dB8CtKN01XWuOq2Yrj6pBaowYsJTjwgAnA113WxrtQwYCkUjvIcBx
         5WEu4nR582VHkZKoqT7/W5TogLDKNV0PmMGpOPKgCPhuq3jZ1Ua283G/JhLCrX55tfda
         cknulB8TjzvBEhkeJ+I/Bes1j95SZAHVKUiFLZDjps/h+HkQJq+x9gDscOI62yIrdBB7
         Zn7u8pOct9Gv7AVa2vfjhv65MUNfsCcIW77ilAq914JYz8KP/sEbzMZAEcoSLyNi5Xs6
         cU5XSg7SeE4Ws/xb+SsCr0vAR/ctmxCGiP98zYg9rKOYH33eAxkB+SgK8PjazitB5suh
         1TXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=azPaND/xFc8atz8F6WN4yBES0vGIQl6FM+kHStQ3aX0=;
        fh=2mEsZPAWRxBRfRO2i3NG+THyFJggE1y/6Xx9bNcE8+g=;
        b=R9MaRE5+iIDwT+5qOZElc5mhGN8H3k6ALlgC76GyD100jDMOp6G39RWcAc3YnTuTgB
         DDwDciDrr3WM5e4Rg4YbwU14yAYjfPQkAAYBZWyoNesx9gkUGeILnR0cqh45vNoyKuuY
         DdHNFZ7AeZFIu9hQN2FWeB4RJzto4Z8YWhdRuto6CJBAp6G3Doa5ndvuKRv/KZUQhRIG
         1xk4uDpsP0IsvzXt0Hvk6k14TDgeJMAJwrZ5cuZELqbms7yGEEs2qs/FANCIseX4JkHn
         DUl/NESst6fyy/i0BvvevjoZcKlk/Qt6lgjMq5SV7xJpdelS3HzTBcL434qOd73piLKT
         YhoQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@soleen-com.20230601.gappssmtp.com header.s=20230601 header.b=jbiyEOFl;
       spf=pass (google.com: domain of pasha.tatashin@soleen.com designates 2607:f8b0:4864:20::829 as permitted sender) smtp.mailfrom=pasha.tatashin@soleen.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=soleen.com
Received: from mail-qt1-x829.google.com (mail-qt1-x829.google.com. [2607:f8b0:4864:20::829])
        by gmr-mx.google.com with ESMTPS id kv5-20020a17090328c500b001db63388676si666373plb.8.2024.02.21.13.11.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Feb 2024 13:11:42 -0800 (PST)
Received-SPF: pass (google.com: domain of pasha.tatashin@soleen.com designates 2607:f8b0:4864:20::829 as permitted sender) client-ip=2607:f8b0:4864:20::829;
Received: by mail-qt1-x829.google.com with SMTP id d75a77b69052e-42e323a2e39so1533891cf.1
        for <kasan-dev@googlegroups.com>; Wed, 21 Feb 2024 13:11:42 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV1P4Q9gh7spRUEppb8ZkLTioFvBLTOw6C3jDiJW+cGyFA3X6bMmEHlVDBaWfPZzN51HU5t3DoyfW3QuV/IS3wMc4SLWcZ8xizn7Q==
X-Received: by 2002:a05:622a:1a0c:b0:42e:3f7a:819b with SMTP id
 f12-20020a05622a1a0c00b0042e3f7a819bmr1401231qtb.8.1708549901753; Wed, 21 Feb
 2024 13:11:41 -0800 (PST)
MIME-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com> <20240221194052.927623-3-surenb@google.com>
In-Reply-To: <20240221194052.927623-3-surenb@google.com>
From: Pasha Tatashin <pasha.tatashin@soleen.com>
Date: Wed, 21 Feb 2024 16:11:05 -0500
Message-ID: <CA+CK2bAs4t1UhLBahnG9GmFYgW2KxdO7PZkPwD4Wbv7oE+aMhA@mail.gmail.com>
Subject: Re: [PATCH v4 02/36] asm-generic/io.h: Kill vmalloc.h dependency
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, yosryahmed@google.com, yuzhao@google.com, 
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
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
X-Original-Sender: pasha.tatashin@soleen.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@soleen-com.20230601.gappssmtp.com header.s=20230601
 header.b=jbiyEOFl;       spf=pass (google.com: domain of pasha.tatashin@soleen.com
 designates 2607:f8b0:4864:20::829 as permitted sender) smtp.mailfrom=pasha.tatashin@soleen.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=soleen.com
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

On Wed, Feb 21, 2024 at 2:41=E2=80=AFPM Suren Baghdasaryan <surenb@google.c=
om> wrote:
>
> From: Kent Overstreet <kent.overstreet@linux.dev>
>
> Needed to avoid a new circular dependency with the memory allocation
> profiling series.
>
> Naturally, a whole bunch of files needed to include vmalloc.h that were
> previously getting it implicitly.
>
> Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>

Reviewed-by: Pasha Tatashin <pasha.tatashin@soleen.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BCK2bAs4t1UhLBahnG9GmFYgW2KxdO7PZkPwD4Wbv7oE%2BaMhA%40mail.gm=
ail.com.
