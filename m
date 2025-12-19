Return-Path: <kasan-dev+bncBCT4XGV33UIBBAVPSLFAMGQEHAUS6WI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id EBBCACCE073
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 01:08:35 +0100 (CET)
Received: by mail-ot1-x33b.google.com with SMTP id 46e09a7af769-7c7595cde21sf2059007a34.2
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Dec 2025 16:08:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766102914; cv=pass;
        d=google.com; s=arc-20240605;
        b=CLBEEaZh9bkehmlgS9wnFWAcfrmdU0/w8pXZkRCpp9y1Dgl/P7YmEiqHrLPcJWCM38
         aR1PEmIF+qVqNCrkNgI7PkYaVUmmkMjxELttBvHQ421GQdmLM6pKMZwimgb3kCwNNGu5
         8Q5e0zUJfrRB75QLthF5fPG5zbjmNYkDLA7W3FXgEPeBc1GDGlK5SdjQwrwZiQlRfAbu
         VmZYu8AhPMOh4wxhW8FLF+7XlsFzlQaKnEejb4Un3x6/6btNYklNNIDdMyr9yfUqSMJz
         P1SCg06pOZs2q6RuZi1WzUgVbCmI382eGyaMcfNnpxVSTFb53f5SIl0Hd3dgF5osM9hU
         PV0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=0cuV2HYuUMUcQgevnK/eDJ1fqdVL+TaNotqjzGzKJmw=;
        fh=VlLkTdiMZ6EA8MuPIzPZBnPblkvjO8PxzArgj19hSDs=;
        b=VHy/iJVfw1zCydI4ANljxypmNFLF1xv1NqM6ZRDBQtKDbBizsRgz4+tUxvlfeMSFDW
         p9Pvucb21chABv7ZBnJOQJdfzuJMhUWAvAv7+SghVODz/jrwML3/Lv3INTPGI0EU7IaS
         DNK87FU2UcKZYCVvah/lpU0S+1V+FWXIER9CiFDY98jMnYJiUB8Eg/QnOM+fUNU11l/c
         MkFuazIhY7oCmKa8VRp5TUNkwATH5/d+Ur+5JL/no7Qow0LgN00HH5NzvU4qA8fCpEXM
         Q0ORLHtE96G7oaqhadII+vLfTkiQELWyc0+s/sKlVxuaYcAF3f+91ZU5pAf/L91u46do
         +oNA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=uPNsSIZ3;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766102914; x=1766707714; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=0cuV2HYuUMUcQgevnK/eDJ1fqdVL+TaNotqjzGzKJmw=;
        b=IcTZ1fmdHaQ0Z/YVeK71fw6rxWHJd6+cJfxTjQC4aTSZgOXnpTv56PGeArlpNXD4sb
         9aISyRQZ7PX9zVvAGlftgJp3nttoMcXkEHWyUvRAgROyNICeaHGsiDt+3JKmhP92IIla
         +iL9cDXPVelGKxiJjMBzR7h1D0fctiEjeuGu787t6GZRwKlnpOH1uANO1g1B1QiEaF6W
         D8jgJD79dVV3gKNUbHsGdrmX1BbNOTDPpxEGOoRER4cMjakKf1r8Q3RGmQiJm5m9Ocp5
         C2d3s+vuuzZOwOdxMFJk9Vt8MJgspP/P/ShjsXQNpVnaSKoeOrLNile3e+bNfDhxH9aE
         MqAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766102914; x=1766707714;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=0cuV2HYuUMUcQgevnK/eDJ1fqdVL+TaNotqjzGzKJmw=;
        b=GMWF7H1dip3d+M6IllNLQN/UXOeXQKJWIl3+Qmi2yJspf6AeX4WCxwKqThEa4eEX19
         ldYVpNMZHrmuGd4wu46a9UwvuY7i5P7hlly1yLbeKu4BkslHrLzpoFIEFkb4oWXT6XFV
         ECLBRGsRcsGv+oIGN8f6nOlcgSmdY6g8YPljePDlqTvzPV6VRgLFO056RtQubqUyhPC6
         0dU1tm/+C95Yrt4wKo2DbpHk9Jxh/uDNVLp/+2R70TPI15O0BeXe02o2N5V70XdMFo6O
         W2bg3lap5mtzu/cwjwX1hk3xe2XQiswMJDjVqU/I6pgum24hgCOFb96xzN/wKbWXnrQ0
         1EDA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW2Tx48W5hPDRLi05JSS3DioT9OyjpPJgounUIhTWjWNqrv4nKl1KfLPWBymDP+gptPwj7ZtQ==@lfdr.de
X-Gm-Message-State: AOJu0YwiYFW8Mxe34+7Sg3Z4DvxLR8zkIkVPQXOzdGJIJS7LfpIRGBKK
	aTR70/uBsV2A3huOyjCtTY8cIi2FI4odmPV5eWVMD2ouV2i7om92UGn4
X-Google-Smtp-Source: AGHT+IFjDazLeRUocnqFV2bxk1xO1Bc2xYJgEGY27X2/mtzjeGPA3eouXXgtQ7odfKEFS4RIj3e9iQ==
X-Received: by 2002:a05:6820:430c:b0:65d:b36:bdca with SMTP id 006d021491bc7-65d0e981737mr460758eaf.27.1766102914527;
        Thu, 18 Dec 2025 16:08:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWbiL2BZ1ior5P/n5ssAMvj3J/PSlZ7Sxq78t8/wjzLB8Q=="
Received: by 2002:a4a:e3d1:0:b0:65c:faa7:7074 with SMTP id 006d021491bc7-65cfaa77504ls1234528eaf.2.-pod-prod-03-us;
 Thu, 18 Dec 2025 16:08:33 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWPb52mXBE7ggWJyiSXlFF4B5bUFwgTUggkuEj6mp8lF0MlLMQ0sH3AsNLq0orY75uwd/VE8cbKqo8=@googlegroups.com
X-Received: by 2002:a05:6830:2e13:b0:7c6:cd24:6392 with SMTP id 46e09a7af769-7cc66a32460mr734763a34.34.1766102913547;
        Thu, 18 Dec 2025 16:08:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766102913; cv=none;
        d=google.com; s=arc-20240605;
        b=L17fse1YaPxGTwLFY5S8bXiVY9fI/uYZREMahwy2Cku7yBkN88O5dbj4RdhHeF5HME
         c0+DWED+JT1N+eXqZaZVyl31Fr5gajYVCUD4QOQ/e0Q5/qPeU0NBxPbhZOduUyZenVMX
         KoMpr8OLQWoZq2o5I4T0HttKfaGZf0gb7YHWx9/PGbtCiMCHoyvRrt3wyyGlden30Zsq
         egJuCsdUJJ9HteUMagy4QJAwC4dw3ha/C2xs4/5f1xufPYWoOimOVBoUshIthdwz2oRl
         laYHiFFmoSa1rcYsTeC8r3nv0xBIbvOVh9O53P8ZrnvlnK2JTe6Ii1pt7ZueQ+Tgtx6Q
         uqgQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=XGRqgNSVS+UDlUcqHaGXkyRi6BhU8rC2UKVCE9VNPvo=;
        fh=QkP/VXDcfyHLTJj12HPj/CHIQ2DjZfQMSVs0aHXXfN8=;
        b=aJ23TjLtC+GnpeXiN9nVoSLTR+V5gAkYv/JyzpJEvrTqV6VorwA5dYbCZxHOuC+TwG
         x6p50Hn2IsGt7srRTAFk/9iGCXQrIiua7RSAR6InAVh2Jg6pSF0M4YcWvnTEQ+9xsNcN
         7caTz3kuNYc/fEMmZNWXWY7WGMzxo9oh8w7ZqK27s0beC/Bt5Hd72Cbxtjd6/j1g6FPA
         PWwU8oFgGZcy2fOtDc955pif7ZluGERt4aYVOXMHsiU8lpEPnf4HttJ3b5qxtdrBvyjI
         Ov/idZVXkSmC3sGEgIuSV8hMiyLqUCuqLLhPxSUfZ1NL+VmEOsYrabzeIQU1ksI99DCl
         NshA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=uPNsSIZ3;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7cc667dedbesi56433a34.7.2025.12.18.16.08.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 18 Dec 2025 16:08:33 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id A114143A72;
	Fri, 19 Dec 2025 00:08:32 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 2F70BC116C6;
	Fri, 19 Dec 2025 00:08:32 +0000 (UTC)
Date: Thu, 18 Dec 2025 16:08:31 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Marco Elver <elver@google.com>
Cc: yuan linyu <yuanlinyu@honor.com>, Alexander Potapenko
 <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Huacai Chen
 <chenhuacai@kernel.org>, WANG Xuerui <kernel@xen0n.name>,
 kasan-dev@googlegroups.com, linux-mm@kvack.org, loongarch@lists.linux.dev,
 linux-kernel@vger.kernel.org
Subject: Re: [PATCH 3/3] kfence: allow change number of object by early
 parameter
Message-Id: <20251218160831.566ae0c0e349e4d563c96c16@linux-foundation.org>
In-Reply-To: <CANpmjNP1tMwdOUTNEqqTmWR2Ki8yDQ+H13iSHxzLkomj-WComQ@mail.gmail.com>
References: <20251218015849.1414609-1-yuanlinyu@honor.com>
	<20251218015849.1414609-4-yuanlinyu@honor.com>
	<20251218155821.92454cbb7117c27c1b914ce0@linux-foundation.org>
	<CANpmjNP1tMwdOUTNEqqTmWR2Ki8yDQ+H13iSHxzLkomj-WComQ@mail.gmail.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=uPNsSIZ3;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Fri, 19 Dec 2025 01:03:11 +0100 Marco Elver <elver@google.com> wrote:

> > >  include/linux/kfence.h  |   5 +-
> > >  mm/kfence/core.c        | 122 +++++++++++++++++++++++++++++-----------
> > >  mm/kfence/kfence.h      |   4 +-
> > >  mm/kfence/kfence_test.c |   2 +-
> >
> > Can you please add some documentation in Documentation/dev-tools/kfence.rst?
> >
> > Also, this should be described in
> > Documentation/admin-guide/kernel-parameters.txt.  That file doesn't
> > mention kfence at all, which might be an oversight.
> >
> > Meanwhile, I'll queue these patches in mm.git's mm-nonmm-unstable
> > branch for some testing.  I'll await reviewer input before proceeding
> > further.  Thanks.
> 
> Note, there was an v2 sent 5 hours after this v1, which I had
> commented on here:
> https://lore.kernel.org/all/aUPB18Xeh1BhF9GS@elver.google.com/

Ah, OK, thanks, I confused myself.  I'll drop the v1 series and shall
await a v3!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251218160831.566ae0c0e349e4d563c96c16%40linux-foundation.org.
