Return-Path: <kasan-dev+bncBCCMH5WKTMGRBG5326VAMGQEYSEKVWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8E5E57EDD6C
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Nov 2023 10:15:09 +0100 (CET)
Received: by mail-pj1-x103c.google.com with SMTP id 98e67ed59e1d1-280351c9fa1sf587906a91.3
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Nov 2023 01:15:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700126108; cv=pass;
        d=google.com; s=arc-20160816;
        b=Fj54xjMncEIhjSqZjTNVz8mwgqbrEyLg8tiVZwegRlh8Pm9PiFMCbYToPrpxlufUIv
         pvS8KhrnA6q2cbjTKVw2dFmbpJPcL+E5tJ5LRBM2g1SfMSPNBU+aSLrwUv95nohxKQLA
         tnnD1Wu28pwbN2LPL+kP3ot5OscskGVLbNg7ouKHj+b3a/7oItxijYaeV7qoSC7PUlSt
         IfRoyM/4CT/kwqNsbfC/C6r8Ks7HQkaSc3Tjyo/BYEcxSij59n5VYvfLnylA+Jo1SYuQ
         /TYG8eTMFdeXDf27wybSd3Ko1HIibWy+D4//ogwRHgomlDqSD2J7p6ntAEnpfeiZ2V1/
         zBLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mvwVmFPDpX14rtCBCbG0VGmuFK3x0eCUvY8GF4MqTzY=;
        fh=YZa8vkdUz4pzRj6QFVU/SyYW+LsIH/Wz0o5e5dUhKFo=;
        b=yyfGPfauR9813UiVkHImUy0pDMrIWmIZsbpukj2eatLzmDWtQez6fg2df2PgOqIrtZ
         BRzsvAV0yBy/f4xqRhqAGjZZH58y3xHHw9uEF+01kmagOLMSer6bZ1Q6VP4vb1c1gXzP
         EXXIqimr6L2LvMh9iTppLEMYp0glII2o7DrEQRFf3g09/RmYdQsOq6GlkaNVnggi7QZD
         Rt4LysK+gjuIf0w11wCFAwuB4sh200FxVCGLf1vpRRG4IzpZMup3twO2sGaYUnFhfdM8
         S+LMwllAQ/IwybKHcJQ7yLA0qsQYo+SgNOK7qrF0LhlvhnZXpsNFU6WcoiqnTAqDTzF0
         B7Jg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=orxl3pTC;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1129 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700126108; x=1700730908; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=mvwVmFPDpX14rtCBCbG0VGmuFK3x0eCUvY8GF4MqTzY=;
        b=VJ23wjxQWiuY1duwO8tmkB1Cozb/EdrgFIIGDA/Aqc19cbhTYv0RefXyUOLPy9uMvS
         oY4bWR8Gb9qe5q6cI1ZfVSOeaWiaKyql0/VhasZftvHQoRxuX1x6Py2HuY/kjaBrizru
         /aGFD0IMkDdav7D/uYN/FMWcvhprhRbjtUCzNk3TFShBVAUBJ7tVfKTuvQJoORSv1hIF
         UB2Pdp171iaNKhPKctYyFXFXwNPrkPz2HTAWgJRyiaK9g4IcApSKcvvOzRcj4ZxtmT2K
         lNz1WCqyoCx5bfHjAorRKa/zbLJqAWZm2w6ofIm28VGMAYst5U2kyzj0fo6XhpaQRPyA
         2cjw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700126108; x=1700730908;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=mvwVmFPDpX14rtCBCbG0VGmuFK3x0eCUvY8GF4MqTzY=;
        b=OxyBut0aV2eR2LzbgEhTnPeWd81E+6afzDgF+j9Z/0EN7riHSojtTurdnQIkuRPVDO
         bFiq5oc5dINg+fLCsXK31WMCnDj7DaS+Z7/tfZWbGUsMigMOb27OanQqRHiVmSkVtRPZ
         /X3eFcgBwT5oi5bDXi62EzoPWyjtIc9kRORHx9SeKDUZlOscwi9N3h+iMHcQrLft8ckq
         KShGoFycOk9sLmqoaO6ku/NqgsvpoCqvxFCaXn35N1oWTZiVfaw0e63BL4n1JyFvOSwn
         RnCwKWZ7kvvT10YrMj1WXVY2Gy5NFvnEU9w5nF/y99/zu4PdsCrMFCZ7MEDyo/RQ+MTj
         RoUQ==
X-Gm-Message-State: AOJu0YzBB5Pfaj3JCrMojYpkM96elu2fyNsTDvSvOekJ4WGwef8i6vSa
	soSKZ0A1PqaQ6EcVrHMA7ZGFEw==
X-Google-Smtp-Source: AGHT+IEhqvVeGRapyjMfXx9O9RYNuDGlg+chPQk8LMAja+hY0DKWwFnKJisi7MdIUJPH2BkYDEPigA==
X-Received: by 2002:a17:90b:3144:b0:280:cd49:2548 with SMTP id ip4-20020a17090b314400b00280cd492548mr13805066pjb.6.1700126108042;
        Thu, 16 Nov 2023 01:15:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:2dcd:b0:262:dc9e:41ca with SMTP id
 sk13-20020a17090b2dcd00b00262dc9e41cals593996pjb.0.-pod-prod-07-us; Thu, 16
 Nov 2023 01:15:07 -0800 (PST)
X-Received: by 2002:a17:90b:1646:b0:27d:1538:e324 with SMTP id il6-20020a17090b164600b0027d1538e324mr13736947pjb.32.1700126107114;
        Thu, 16 Nov 2023 01:15:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700126107; cv=none;
        d=google.com; s=arc-20160816;
        b=Cl/H8D9PWgSpJWvtOd4teDGBxUqforAymwcaSBlKg/mi68rI/6Asqs9oslmaMdoW7z
         NtlCORfxPSdmWmzKqhJx7qW/4Z7zrQDSuSMrmN0h2pzY/OxNj5McejvyJ7ivSc8RpSdh
         FMd73Fm671wGiEaeLwytClbLrKqH0ZyiYuQ0hyT8mSTameM+P3xnWFmJO46vtseFOTko
         17HoUOnYqVYiUNzXFhs6Vd6LeJvsgReH6JTGjEYnW0u+4QGUCXRtwopBSQ/hWSQBOD01
         YN8mvz4zMSOtCfW7I0ZECChvYjeRb4q7jY8fllgHVSb+qw0McUWEFFePAcL1Kgxzkzci
         6iKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=QsOxPTssCXfEjaJKL1FvlaQBMDAuXe1RlMdSNjLvudI=;
        fh=YZa8vkdUz4pzRj6QFVU/SyYW+LsIH/Wz0o5e5dUhKFo=;
        b=HPxLeD4UUsfLu693dSRDWH+9SvU3sGFE00h5azFEIoCrloctAdWP90eF4lXJw+MTQl
         UpQvFWuTMvywZI1nZ3tWRABsAkCM7I5MchZ1bfpwZkXakqQ1/QSWgFz6dQ7a36kvR49w
         d4GccwnrMRFV7KvjxJ7CTTYhZ8SNKOKxzqlmhb6KLivUz0fNT5TKvdMMKm5yR2ShlRMj
         m4K+8tGkIWnJLKvK3HWr8QQIVGE9T3/alMcNpH+hXMpcsGRNMxzfxwDdGiK6vSgav5it
         cHs3HMbuZ0QjNYyWzHNMqu77aH9H5jVEhM7s1OuYEt9EM+s/nJ4V8U+OkIIeWYLZCxO9
         zqaA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=orxl3pTC;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1129 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1129.google.com (mail-yw1-x1129.google.com. [2607:f8b0:4864:20::1129])
        by gmr-mx.google.com with ESMTPS id qb4-20020a17090b280400b002802f4698f7si110920pjb.1.2023.11.16.01.15.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Nov 2023 01:15:07 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1129 as permitted sender) client-ip=2607:f8b0:4864:20::1129;
Received: by mail-yw1-x1129.google.com with SMTP id 00721157ae682-5a7d9d357faso6040007b3.0
        for <kasan-dev@googlegroups.com>; Thu, 16 Nov 2023 01:15:07 -0800 (PST)
X-Received: by 2002:a0d:d70d:0:b0:5be:b764:a15f with SMTP id
 z13-20020a0dd70d000000b005beb764a15fmr15877402ywd.24.1700126106526; Thu, 16
 Nov 2023 01:15:06 -0800 (PST)
MIME-Version: 1.0
References: <20231115203401.2495875-1-iii@linux.ibm.com> <20231115203401.2495875-12-iii@linux.ibm.com>
In-Reply-To: <20231115203401.2495875-12-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Nov 2023 10:14:30 +0100
Message-ID: <CAG_fn=X6+fgYb8THhb4GyZYz_1mVxAifbBeA+bOqDCmmT6Dovg@mail.gmail.com>
Subject: Re: [PATCH 11/32] kmsan: Export panic_on_kmsan
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Marco Elver <elver@google.com>, Masami Hiramatsu <mhiramat@kernel.org>, 
	Pekka Enberg <penberg@kernel.org>, Steven Rostedt <rostedt@goodmis.org>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Christian Borntraeger <borntraeger@linux.ibm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, linux-s390@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Sven Schnelle <svens@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=orxl3pTC;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1129
 as permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

On Wed, Nov 15, 2023 at 9:34=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.com=
> wrote:
>
> When building the kmsan test as a module, modpost fails with the
> following error message:
>
>     ERROR: modpost: "panic_on_kmsan" [mm/kmsan/kmsan_test.ko] undefined!
>
> Export panic_on_kmsan in order to improve the KMSAN usability for
> modules.
>
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DX6%2BfgYb8THhb4GyZYz_1mVxAifbBeA%2BbOqDCmmT6Dovg%40mail.=
gmail.com.
