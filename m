Return-Path: <kasan-dev+bncBDW2JDUY5AORBBHO3GYAMGQEFJ2VLFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id C071189F092
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Apr 2024 13:24:53 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-2d86a38bb94sf46603461fa.0
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Apr 2024 04:24:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712748293; cv=pass;
        d=google.com; s=arc-20160816;
        b=EHHBLRA3VNxkB9RMCHMSvuAk0lc52INs4/7K4sIyJ4d8SmcKX8gllCgpEaQbU2SfCf
         AtGr1MvQubZSQsuOVMyAiSTwpOfUDEJNVY2fLpkIo/Q8HhObWb1RvkR3YkTPoXasR8eR
         RIms5b0zC85HCDDrDkXU3y7O/6ldvp7XsMUAUIYFiMVckqXNolVB2DfPslIjMA0jB1rj
         c5ihdWB6lxxEWYIvK1e6cArxYXW+QHQqUd9k/os737jiyYIuan8osDWA3NfcoBElsAF0
         SkwBIPhw17VHG/YiQ7m4N/meOe5TThRuLvZqxwx7RAt9i+ih7N0OchfMPi3ilvCo8bs0
         BnGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=reDMOcfHY41Py5PqH+KzdlVi3fqAnU9H0KmXi+Zt1UQ=;
        fh=VrJ+6jahkV1UPF5393PMay+AlvKQ9/mFlIA0E+wOaSc=;
        b=StYmdtmsgowDYnhuF8Jl1u3Nr6PiuuS4VUlKig1x8mnwQR/L0c5KRcBeSS0dC4s4B5
         6PdlzK3MRnLEdA9qGG/EpGWahrtuP9MtUctmDIDwnZ+fLOGxK9gRQqkfls6mMTKMBq4c
         tFBGouLvdmWCEx14lY8p01gukQ0UM0p5n07OedX9clyf1i1NAaxsS+EUnQltl77hkptl
         1+0HAoXyptRhyUb6pOdplyduvLAkTG6+ec08wDKwvDcsz1DYI84mxcgNZgxTYe2VUXkB
         p6d8BcKpVJwRLZmf8pxuRrmLawgmNNf7yjRQXtFzfCx60n8dreLM9oFHFIYiachjlx7x
         3MIg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=gVUc5IXz;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712748293; x=1713353093; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=reDMOcfHY41Py5PqH+KzdlVi3fqAnU9H0KmXi+Zt1UQ=;
        b=IIRCBcKpgl4kznG9m4F28lJ6Y/lyHEHh2md4HGQMrAt9w1+SYc+nxoB+FtyZWwgdUA
         sLIkrNdLLJ/AhC0XxjktmwUU4lNATEq9sS3BUGazxcT2/c58YdtuoYJiwV0DQJNLnz50
         gQyfXfWFW999maQVRL07aA8RfddVaENu74HXFX9cHfYih+FVECttj5qAcWHq9Wcd7Dha
         VLG/Rv2EFFXej2w+yejS5TJjfgOLSDXDrL43Bj1CJpsV9gDL8pdH4et5b+K7O1GJCW8m
         dGd7rbB/fW+31e6zC153r2ZZ0i4u7PGUpfagylqnIfvd765tPdqq0j/vkGrMJiV2rgP/
         tw8w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1712748293; x=1713353093; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=reDMOcfHY41Py5PqH+KzdlVi3fqAnU9H0KmXi+Zt1UQ=;
        b=Hx/urbxxAHfnR56fiyN8aCxY2OJp9tT6uGZdjzuD9HDriYhutB2ODQAI0wlGzyoli0
         ndeZAbcRFxwhaXF7C//AmPHhXdf6eImop5Lxo9rCRZhxTM1pd0qGyMOwsMhuby28EhWV
         0SDr8fuGJmPrhVnoiWQbKUXJoTmtUpILmQOnws/qmpdAQ938WDsVff/9kp3fPzLZ17mZ
         x/ZGP3pWbAG5g4Ocq7U7CUwE/CbuJKdtzBeXLKH9MhGCyFQuf+6DesUpkpGqvKJ38Uq7
         FNsrgJ2uTYIrxat6LGvEEcTU+02nPgxo5BvPxu7pD2n4Hz66v8m/PsBDzfaKmv5jyDQR
         5TsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712748293; x=1713353093;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=reDMOcfHY41Py5PqH+KzdlVi3fqAnU9H0KmXi+Zt1UQ=;
        b=TINMiOJwOTey0S0+J0dEOgDo/wMyG0kpv2377guE62xPxntaKYD3tt1F43sj++18EU
         r9i4IPYYswh3/JUjkLHw1zyPR+HxgOiFDyXcRSJCEVwDkhcMpKLx4n8NLF5+VFm16YN3
         bfTekXOJ6gF3sh8W9vlpbSvTls1btOxCVZLmkzHTYsto5BaTdIX0OwQYCEr67U170Juc
         IY7HAVarXRrJT2Kv/La5fIsr+SZI6W8c/Ie5QhFduHIezKtCt9dVheeaYJCdLV0CHcnr
         bRDrUNl0rLw4+qV5q6y4trU7wfevIdetE9ZKtNjbEJfZ0nVvt8axuk77EFy0brbgizdT
         B02g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU6gytuWKAZU/xbossWkWyx9BX2Wn15ne9Fer7onPbbutEzkGo96iEAt0Ux6PmrhhNoThDcVIhAmoKcgcS4d0WmFJppRcPF4g==
X-Gm-Message-State: AOJu0Yxx9dNNVPqVkCHZcHMoR79PBJubYcDrsJjt6IEtwTtYTSH3APmj
	1I9L/Do0PnezQNZdYHGqFhV3ssoPD26AloHtnacKVpfr/CBSTKRD
X-Google-Smtp-Source: AGHT+IEh8HfeTx5S0jf9c/3Gli2GeB27i9DGyApTkl97+EKrh7aEuhlJNrqJ9txieov6JvBL1kdDnA==
X-Received: by 2002:a2e:a9a6:0:b0:2d4:1fa4:9eb8 with SMTP id x38-20020a2ea9a6000000b002d41fa49eb8mr2031201ljq.40.1712748292630;
        Wed, 10 Apr 2024 04:24:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:7d0e:0:b0:2d8:4a5f:4867 with SMTP id y14-20020a2e7d0e000000b002d84a5f4867ls591548ljc.1.-pod-prod-09-eu;
 Wed, 10 Apr 2024 04:24:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXS4cYQsjXdmJ8KVuNbsaAnwohhS2gzQMUNU700toLIq7BRz1OJsyiv9F9JS05qOBvL1bozVk1p4pUYEYTX3I01Gb2Laq2wtAHe5g==
X-Received: by 2002:a2e:9989:0:b0:2d8:74c6:c44c with SMTP id w9-20020a2e9989000000b002d874c6c44cmr1395571lji.46.1712748290626;
        Wed, 10 Apr 2024 04:24:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712748290; cv=none;
        d=google.com; s=arc-20160816;
        b=xgG5Qv8ASwfN7nb5fTB9hmViQ29YvsecRz6+iWusqFbWGHUC7o3Z8iRVHD1Ly1ALev
         2IlstnHuiaqDVLaswevzEdhLobCe+SxHPylW5XotNs7TaUW61nTO/LkQlkcBuFbRUriG
         WW/PDSxl1LlsG2cg3bF9v8ZpsYXljMok+m4hVjCpJQvDqcM429x5wNHlwUeS0prUmsyh
         Z29Na1M0R9+0h09B59NlbsKZ2PiX8y0d5/ksh1yJWxRSFPIL0zbgIUKPLKW76B5FKm4S
         AQj4jvR0+kkODzhu6WAwVJvGmCMInmf3a7chQd73pgormfItJs6jFznHuv86GSvEtENv
         48iQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=RulsX+ZQ0xI3FOCjWtjixDk2aZyRKbqsfynJZlC85YY=;
        fh=/20dOCJq+bqfKEpdC/0w8OHbjF9ugoVM3URiCCl5koA=;
        b=ERtBkVdhrnbVjeBvxSm5URSckVl0cvGtmPHvJa+ZybF8ztjCOLMWnjqj2WQ6S96Kcw
         DYY7w0q61j1hLiVJ+vRQq5DOREZCb7yiUNu9gLulLLcMHBLFb0pyBnamLmdcScAYmK0M
         NsSgyIKh+tUc9eh8QZ3MTMeGG+zxMJzYx1okL8AXgnqWqOOWz53UIm3ATWtSs0b7g5SS
         LxG4lMvNDXHdhFBoIJxT3FkXUvIxRY57OM8qgpnmHmR9HwPZBghHhCCBWkcqMjNZKj72
         yNcV+Z6hXAjMc7FEzCWgRprlx6Scze1ilxq/h2Ahqnw4zVHRfCkeKzPqtogkyeXc9Ufz
         f2Mg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=gVUc5IXz;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wm1-x329.google.com (mail-wm1-x329.google.com. [2a00:1450:4864:20::329])
        by gmr-mx.google.com with ESMTPS id t20-20020a05600c199400b004166a35d7e4si168058wmq.1.2024.04.10.04.24.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 10 Apr 2024 04:24:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::329 as permitted sender) client-ip=2a00:1450:4864:20::329;
Received: by mail-wm1-x329.google.com with SMTP id 5b1f17b1804b1-416f04059beso3166725e9.1
        for <kasan-dev@googlegroups.com>; Wed, 10 Apr 2024 04:24:50 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVdpyUQbDf/zzn6XdSMLJi1zzyXtlMzxRdIBRkfaXKLwHU1kEnJk/NBign733fTOd5rg/n+Kvll+X5SpFowoeQnlNzyWgy6dU/Dbw==
X-Received: by 2002:a05:6000:1ac8:b0:343:c58f:7af4 with SMTP id
 i8-20020a0560001ac800b00343c58f7af4mr1603177wry.59.1712748289941; Wed, 10 Apr
 2024 04:24:49 -0700 (PDT)
MIME-Version: 1.0
References: <20231004145137.86537-1-ubizjak@gmail.com> <20231004145137.86537-5-ubizjak@gmail.com>
 <CAHk-=wgepFm=jGodFQYPAaEvcBhR3-f_h1BLBYiVQsutCwCnUQ@mail.gmail.com>
 <CAFULd4YWjxoSTyCtMN0OzKgHtshMQOuMH1Z0n_OaWKVnUjy2iA@mail.gmail.com>
 <CAHk-=whq=+LNHmsde8LaF4pdvKxqKt5GxW+Tq+U35_aDcV0ADg@mail.gmail.com>
 <CAHk-=wi6U-O1wdPOESuCE6QO2OaPu0hEzaig0uDOU4L5CREhug@mail.gmail.com>
 <CAFULd4Z3C771u8Y==8h6hi=mhGmy=7RJRAEBGfNZ0SmynxF41g@mail.gmail.com>
 <ZSPm6Z/lTK1ZlO8m@gmail.com> <CAFULd4Z=S+GyvtWCpQi=_mkkYvj8xb_m0b0t1exDe5NPyAHyAA@mail.gmail.com>
 <CA+fCnZen+5XC4LFYuzhdAjSjY_Jh0Yk=KYXxcYxkMDNj3kY9kA@mail.gmail.com> <CAFULd4aJd6YKXZr=AZ7yzNkiR4_DfL5soQSvhMhNiQEPUOS87g@mail.gmail.com>
In-Reply-To: <CAFULd4aJd6YKXZr=AZ7yzNkiR4_DfL5soQSvhMhNiQEPUOS87g@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 10 Apr 2024 13:24:38 +0200
Message-ID: <CA+fCnZcB5GuwUx7SPKyCMVb2V-dc4GkJbY2PvmzhqHB5vszS6g@mail.gmail.com>
Subject: Re: [PATCH 4/4] x86/percpu: Use C for percpu read/write accessors
To: Uros Bizjak <ubizjak@gmail.com>
Cc: Ingo Molnar <mingo@kernel.org>, Linus Torvalds <torvalds@linux-foundation.org>, x86@kernel.org, 
	linux-kernel@vger.kernel.org, Andy Lutomirski <luto@kernel.org>, 
	Nadav Amit <namit@vmware.com>, Brian Gerst <brgerst@gmail.com>, 
	Denys Vlasenko <dvlasenk@redhat.com>, "H . Peter Anvin" <hpa@zytor.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Borislav Petkov <bp@alien8.de>, Josh Poimboeuf <jpoimboe@redhat.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=gVUc5IXz;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::329
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
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

On Wed, Apr 10, 2024 at 1:21=E2=80=AFPM Uros Bizjak <ubizjak@gmail.com> wro=
te:
>
> > Filed a KASAN bug to track this:
> > https://bugzilla.kernel.org/show_bug.cgi?id=3D218703
>
> Please note the fix in -tip tree that reenables sanitizers for fixed comp=
ilers:
>
> https://git.kernel.org/pub/scm/linux/kernel/git/tip/tip.git/commit/?h=3Dx=
86/percpu&id=3D9ebe5500d4b25ee4cde04eec59a6764361a60709
>
> Thanks,
> Uros.

Ah, awesome! I guess this will be in the mainline soon, so I'll close
the bug then. Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZcB5GuwUx7SPKyCMVb2V-dc4GkJbY2PvmzhqHB5vszS6g%40mail.gmai=
l.com.
