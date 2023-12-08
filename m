Return-Path: <kasan-dev+bncBCCMH5WKTMGRBCFWZSVQMGQE7NPPMJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B9E080A478
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Dec 2023 14:32:57 +0100 (CET)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-4259aafd543sf12308221cf.3
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Dec 2023 05:32:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702042376; cv=pass;
        d=google.com; s=arc-20160816;
        b=Y1Yyf7FkYhxInoznjpL+Gb+1eHwkF/qNOTcvor/bIa+OeMUDn28kpcCSb7b3DGmt6i
         Hx2gWcleuOCmnhR4LNIpMmHt7UpgOOUQuiqoYtPKwnVi8qm/t7dGpRUBMEkvbfcETgYQ
         zIY4O3wRE1Uh0nRkeznCbXHAOk6fJEsmNXyh2kP/0SnqLZ8athwUtqEA+7zmIqlYT2y1
         cuXIBFHdcmwGnmQKewe7qct4/7DCMr+1xoQsgIngx6W2AjZmYH5MjqXEvyjU088lXZS/
         MWf8maMDGP3dn5xMYE5owB8NhAC4HqZPUGIYaJOwPhk1s03WoU3mYlIvWZzBC76MJ6BY
         Vy6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=d8YiYamIQDNcPD2jJgIsx/yl6cDJyYRxu5PlhJ+kHuo=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=wB1kBGWd6jt/H1OSQ2OfV68dW4NhFbnjSP2PdQFX8jhG3VirlXoQ3XiLVr+RDitP2+
         WVqr24TK0bo9dQ9ENTq5mgHo7LfKooHKyOavn36uxwjNeTcjnX5LZSfAwZwLFcE/ZykO
         BwIPKfgqdyVNdqe0KM3rDR6skaqNLuSPw2K55nrQ5RDFFf7zA/jQTdt/io1XKiHZp49i
         7H/qBYpMXHHi29s0Od9GlyNDXOXNbA9+pe/ax0h/Dh9jieZa0zUfoUk/c99i6sBhO8WS
         agm3mZsoIEOZp4Sw0Pma+vwEgCc90h9h5IamRL3Bt4TAbQuSDMbTuN6OdTHuvo07rD88
         BVDw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=aE316bym;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::c2f as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702042376; x=1702647176; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=d8YiYamIQDNcPD2jJgIsx/yl6cDJyYRxu5PlhJ+kHuo=;
        b=hPzoCi5bAwRMEpmFUTWzIheCYrPH6ly14654trkTp3bW7RRlgq7d439JDR7upNC3i5
         UDP9Jw1C3FKP2MpKgmVFhJoXYHZ/15Pj036cOzmRqmY5jNq9XQ052BzPHvnfDBR1HQ7M
         NfW0oYqf/OWj58EJ94auSeuOzkQIN5hgDPB0/9hdKPTC1ReHMa8hcSnpId2ag8Q29bji
         fHa8Ts21Hcwcggt/PP2tGsXEtGGXF3V/q/DUxU9tlUA9YR5HaU+8jtfbxEJPAe8TcEtO
         pN3kOyhywsruCaujWrrxXus+0nhlHX14I5BXr3LPzX3ul8YqtA5mIV+QWfkaaDYZVFqC
         7l/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702042376; x=1702647176;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=d8YiYamIQDNcPD2jJgIsx/yl6cDJyYRxu5PlhJ+kHuo=;
        b=qnoZgIAIBCxnF7i9N6EKq40lzfoV6a7R1cIlDXseVB3D/GI1KYwkgNeYwpGhoIDe0w
         vBsIwDC2ChtPGxfzKCwChZntrN7vV+1598fMx43LYyE8Qk0sWiAwzfeGN9/7slxs9sv+
         4LbchddxZmc7c4Dj2i/TvXX6XyeoYiOYRAPz/yRiUrPekKvMBPf3r38kwLe0OqZI7pTr
         NRKN8tbfcnwIboeP9P7+hcevk5XnXsot4I3i6GxVXOL2oEMD2pOnDhQKA+/dbqBRW/ZW
         ICvT4+TrHAOF7xGkhq/ieu/Ut0Y9mV6nIWXdOTWcMXf4SOMpWymSysDSJX2SyAdIMvWr
         COog==
X-Gm-Message-State: AOJu0YyFA4eBGzAzZP6kjdby5tuHhAFVTtF9l6T7EqmBwuWSHgdXW73/
	KEUFFj+bm6WQBXLaZ5eAxMA=
X-Google-Smtp-Source: AGHT+IG9waOSOgoA7VcFF6Vzfsm1gjOFxrLZP9nHo9qmAZG8I84w6TsxvN4sYwzWPB+VA1/2DZsnpA==
X-Received: by 2002:a05:622a:1207:b0:423:ffc3:c26f with SMTP id y7-20020a05622a120700b00423ffc3c26fmr115077qtx.34.1702042376325;
        Fri, 08 Dec 2023 05:32:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:19a2:b0:423:7c51:c731 with SMTP id
 u34-20020a05622a19a200b004237c51c731ls2467597qtc.2.-pod-prod-05-us; Fri, 08
 Dec 2023 05:32:55 -0800 (PST)
X-Received: by 2002:ac8:7d03:0:b0:423:723e:e5da with SMTP id g3-20020ac87d03000000b00423723ee5damr89867qtb.39.1702042375599;
        Fri, 08 Dec 2023 05:32:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702042375; cv=none;
        d=google.com; s=arc-20160816;
        b=z8fDJceOdELaGCHbFkZbZkuL7ZaE2Y5Tu+uxgew4UfAIhl8fc35jYLbodMT0VA+kqt
         lQ4tZEo89Atqx/UYtiTqYCkZIX5bxLVtc+x7n+HQl0e/IAcF9Qee805P17QQHsni9DQc
         SYECOdOUKi/fVFd8S94VGkZx+v8ZVE6IfFhhQoktPVJc0NZ9vuNIcTtqFAkxzl/MSe1u
         +ZaITm/UAIw2MAeoJAlT1AJ0UpuOKzz0c+dnyIFnFwyKiuNETeliRUkrSa7Myzioeakn
         a56JgmC8n53HZ49N61epPAidiesMW81XZxLtyYk4f0uj0J2Iboe4Cd8wklxYZAPGfeA9
         gibw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=pL1EkEt0qsAoRDwtVA7bs3ZuCI4ZBobSjrqprT3lLqo=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=hCaVgLgRQm7uAubeILFeRcWxcBRiTdVghQKN9c3yKIDPQkS20MhZHMRa8cnV6qDOjU
         bNtHlCTXYlglx/OmWa4aR/ItiJf421NnzmiiIbJn612ZeQZVsyzZf1LgabCoLWrMlWe+
         ZnJxuaNfJnjU94CmW3b9pHje3/LbAXr7jEsjv6lrd8CDZHt8DEb7SUQExwRmwOQUf7cm
         RK4mlvf39xsFjZqf0Xq8+XPl9ByG9gpkY1y8a0no6BDqCHbd5DgZ1snnu6YoHl9uC8Ko
         E5LJK4HPrS3m/0fCbDArJA8bMZ4KVwZY0JyYfz8+5uKez4YojpbDKjfXOp27AMPdznRu
         HawQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=aE316bym;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::c2f as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc2f.google.com (mail-oo1-xc2f.google.com. [2607:f8b0:4864:20::c2f])
        by gmr-mx.google.com with ESMTPS id fz5-20020a05622a5a8500b00423e5a4fb24si418549qtb.0.2023.12.08.05.32.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 08 Dec 2023 05:32:55 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::c2f as permitted sender) client-ip=2607:f8b0:4864:20::c2f;
Received: by mail-oo1-xc2f.google.com with SMTP id 006d021491bc7-58df5988172so1034118eaf.0
        for <kasan-dev@googlegroups.com>; Fri, 08 Dec 2023 05:32:55 -0800 (PST)
X-Received: by 2002:a05:6359:6196:b0:170:22f1:d0a2 with SMTP id
 sb22-20020a056359619600b0017022f1d0a2mr3474879rwb.56.1702042374871; Fri, 08
 Dec 2023 05:32:54 -0800 (PST)
MIME-Version: 1.0
References: <20231121220155.1217090-1-iii@linux.ibm.com> <20231121220155.1217090-20-iii@linux.ibm.com>
In-Reply-To: <20231121220155.1217090-20-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 8 Dec 2023 14:32:15 +0100
Message-ID: <CAG_fn=WiT7C2QMCwq_nBg9FXZrJ2-mSyJuM1uVz_3Mag8xBHJg@mail.gmail.com>
Subject: Re: [PATCH v2 19/33] lib/zlib: Unpoison DFLTCC output buffers
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Heiko Carstens <hca@linux.ibm.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Marco Elver <elver@google.com>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Pekka Enberg <penberg@kernel.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vlastimil Babka <vbabka@suse.cz>, Christian Borntraeger <borntraeger@linux.ibm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, linux-s390@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Sven Schnelle <svens@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=aE316bym;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::c2f as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Tue, Nov 21, 2023 at 11:07=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.co=
m> wrote:
>
> The constraints of the DFLTCC inline assembly are not precise: they
> do not communicate the size of the output buffers to the compiler, so
> it cannot automatically instrument it.

KMSAN usually does a poor job instrumenting inline assembly.
Wouldn't be it better to switch to pure C ZLIB implementation, making
ZLIB_DFLTCC depend on !KMSAN?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DWiT7C2QMCwq_nBg9FXZrJ2-mSyJuM1uVz_3Mag8xBHJg%40mail.gmai=
l.com.
