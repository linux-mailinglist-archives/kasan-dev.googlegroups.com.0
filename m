Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCWH3W4QMGQEACJMXFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 281509CE954
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Nov 2024 16:06:52 +0100 (CET)
Received: by mail-pj1-x1037.google.com with SMTP id 98e67ed59e1d1-2e9b1383da2sf998146a91.3
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Nov 2024 07:06:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1731683210; cv=pass;
        d=google.com; s=arc-20240605;
        b=GrJOnuddpuPBXgWrQdm4U8M2dztIEHxR0LP87IW0sXXACp+lhMjwLTpGTaTzICzoXL
         FJdbEH8qzmiHg2LpHg3c5g5oRsHJe6oF6L7KHTJ0eR+15l6hcoqZxFGuHV2jX4lJqPc2
         Q9CRi+YTgb/trwWz4voHAqwaytq1AkKjB1cODFbAXKw9nBNOHKAfhklxbVzHZ/IDDioP
         euh4WxVKb/tc5hmOxpve/1zzRcB2sV1GCJbvNr1IGcJD6QPQQXV0ZFO9/j/262IxdLUG
         CoUwaDvXVf/yx6X2PQfPFVh9u33/LDzdhiMdS47/OuastuY+YUYQ5q0E9NhsZxBBgGwW
         E0cQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=yVUQ3APzzMOPpFWl6BEGvh2fL5Vfv8N0DB6jA4xRqm0=;
        fh=HHQqAo3MTs6nMcEPrgSZ3bDChjjK7UuHqsBsm4ai0vA=;
        b=YzupEa82E0NLjWyWldfPPYBq4qtZRCSWYsS241zp/n1cGDZNRU4tPiXSX7Ru8qJ+FV
         hlgdg1VStlbQs1twHSo6tjSfVGAEKD9CeZcHwAxx6gC1W/ks6lVc0tkaD5dyy4x81R+o
         vILcx9amFTKm3ohX8UNtc10ggh7xCOqs46BlNf61jGLo6UlJtLKZ52DAq9JQdPPjDVxA
         5Oh1sd9fOGM1v+kgE8jd1S2XbnbUfHdL+OpyAlTvZj6/osU+nXfO1Dyf61noNhd9cmig
         OlnX56qMJIBSFjgtaSiWq7QJnsFZXoQB6B6EFm5rB7AcBX4oW4cLSf1DadU7vLVyhOGV
         +X2A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Ujhckukl;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1731683210; x=1732288010; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=yVUQ3APzzMOPpFWl6BEGvh2fL5Vfv8N0DB6jA4xRqm0=;
        b=pUQBfEPm+aAQtJYTAEtbbVMOT94Rk50nya82UfesCZcTyglGW9eOeRtDgOAn3wKCR9
         kXCTnBgLER4LbsRpOROmUxfZU2nofkqVRNl1P+Eifb1vKgSRpY7jwmworRHatocuABP0
         rXfxtbouXnzcXbZ2mLkwsajDFIrzpVj7ATJM1fr9E8li/UIiS/AY9tbjD2o/hjp2vALJ
         9ieoVVmF3J1WoSx2KCw2Q2mLpvonX59fhgbGCpcvTG+N3Baas2Y3XcKl/szH0/RxirwU
         otkul/EJa/zu7Wzqh+oU/oHxajyD5gmfJXcqBJWkh2fa0PBSkVc7LkKefuXmswgb/zzs
         JSpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1731683210; x=1732288010;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=yVUQ3APzzMOPpFWl6BEGvh2fL5Vfv8N0DB6jA4xRqm0=;
        b=ikyvhLRHMm6rtCAOKdlME8t5SKtgq3G8WSxjSKExGpXjeAJNSil+YqN6sdP95ucqH0
         9fGx56gHEqt6ETiZhqqZDEoxNn+kBvMgF9X0rVPqZskWcfkJhVGK4+yZTmxi7OMZZXON
         v2Nbt0Ka8vrVpkIO0+j5ozblj24mMNkjtNzWph0ltxlasdPlO/77nwg72b6teiU4z5gF
         jmPgIZdUPPHpH5+6gmn6Fvqri7delHstkL9FF7Uo/GZrkpOJ8rRCRolKvCbOWxFPGQ1E
         +NLbMUUCgLzMdYla+MwNG7Xvig6y1WMTzTumlOc5QZ2yJnuq3+83gKRhg42l+vKMJMOh
         H1GQ==
X-Forwarded-Encrypted: i=2; AJvYcCV7hvyL1NsZne8xd8qDgVhZu8r5qfgzm94hHHTNJaZ/SwVExQoe/0EWoCI2N5H5sqEcwsmhRg==@lfdr.de
X-Gm-Message-State: AOJu0YzeltuH4MPRtx06m9uvhnhqPtCyfan3Bw+9aFNY5dUwOu88Ul8H
	blXoXYrEh1ga9MZwszzyfFo073zviHkXxYFhUfF3A96jl81sMrfs
X-Google-Smtp-Source: AGHT+IFjrnnVAMTMba+Vq71qbmc0VxC+xneY8VNmXL8c+nwniiyIJ3xzhDtwd6js90pJ2LqOrzFnkw==
X-Received: by 2002:a17:90b:2e0c:b0:2e2:b462:1d21 with SMTP id 98e67ed59e1d1-2ea154f6e4fmr3788781a91.10.1731683210302;
        Fri, 15 Nov 2024 07:06:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:1282:b0:2ea:f53:51c with SMTP id 98e67ed59e1d1-2ea155b3109ls705100a91.0.-pod-prod-03-us;
 Fri, 15 Nov 2024 07:06:47 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUEn239V7fWkO8e72PETurZ8CafKbFuGF7tQDoPYpKwk5/Q+kgjCRIdT6htGRt9mmvPr9FCf90ueA4=@googlegroups.com
X-Received: by 2002:a17:90b:3bcb:b0:2e2:b2ce:e41e with SMTP id 98e67ed59e1d1-2ea154f722amr3488302a91.13.1731683207107;
        Fri, 15 Nov 2024 07:06:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1731683207; cv=none;
        d=google.com; s=arc-20240605;
        b=KlsytDO+56SAxiXiw+MW21MzVHQVJRBL2qnv+nnSgEP6+cE1cfHr6JgB05U/cBwQFI
         tdFxqbtaxXF6QL7jTMeHc/H54R48bCon1e+THbGI5g6bIo0y4aTckrPkyx8ZWTJSZYy/
         grh+W3YMg4sSuTnkiDUNXcIqC8qUC1tptOLtIFYdSRawlfGC34Vxijuj869q1dnsw/wn
         lkVS/ydORQNZjOqEEqGclh+Ru0NyE3SGNJjSzZ7NyY+jkcVcRk6/ewrWXVenKigAJUzV
         +/+FUbERJdumkMnesTmQfnG121H08E9nQZl2J8EgXM5eEPX8Jz7+Tm5SoaE6F4WgDz8M
         5Y/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=L6rHc7bIH39FF/0gn7erG2N5q0A9lM5z0Mr12TL8uZA=;
        fh=eQZD6OQ+FrlLgkJMe8Viu97qiRgrBKz7qSKUOSmKvP8=;
        b=cypz/QMauZ5vrS1xc3+URbG1t/ZAJCUoX6J5YIrb+lyxTBvqtZ+WqZ/REcpnaOuX5k
         YjawufFd6js1FvlP268hjvkCKs5wLFXV9ZDU5EtvnnSs/qBeVbjYaL5l4Cnoa7DDaakA
         DDb7DXWv7Hvvv7Zg8206IfRjkAWaBs89QlQmtr0gKp3F4i5/1AvVhq+m7pmr/SklutoL
         xksiKVziG8sHY4Bm3JhBpY4qYAqw+Jizg2pC+9e+ZO4n6ftesb4OCFfE8Xexgtxb3tvH
         0NI3Guzijs9VvdqDqh76wp6ckk4XxyTHyzx4y7zpOGX0s6W086UQpT2e88oH7/CvSG/R
         FBsA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Ujhckukl;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52e.google.com (mail-pg1-x52e.google.com. [2607:f8b0:4864:20::52e])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2ea024be90esi279395a91.2.2024.11.15.07.06.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Nov 2024 07:06:47 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::52e as permitted sender) client-ip=2607:f8b0:4864:20::52e;
Received: by mail-pg1-x52e.google.com with SMTP id 41be03b00d2f7-7ea76a12c32so580369a12.1
        for <kasan-dev@googlegroups.com>; Fri, 15 Nov 2024 07:06:47 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUKOGQF2WmLu4rxIA6ydOXzF7awtXoyb/4tMWzfOZUi42RsX2YllhERvHkbqlD/p0pabkPJ2HMcFqI=@googlegroups.com
X-Received: by 2002:a17:90b:3b46:b0:2e2:ca4d:9164 with SMTP id
 98e67ed59e1d1-2ea154f71e0mr4241757a91.12.1731683206476; Fri, 15 Nov 2024
 07:06:46 -0800 (PST)
MIME-Version: 1.0
References: <20241108113455.2924361-1-elver@google.com> <CANpmjNPuXxa3=SDZ_0uQ+ez2Tis96C2B-nE4NJSvCs4LBjjQgA@mail.gmail.com>
 <20241115082737.5f23e491@gandalf.local.home>
In-Reply-To: <20241115082737.5f23e491@gandalf.local.home>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 15 Nov 2024 16:06:09 +0100
Message-ID: <CANpmjNM_94fmQ025diHd9_vKtRxtDbSYaOpfBbshNQYEPQmHZw@mail.gmail.com>
Subject: Re: [PATCH v3 1/2] tracing: Add task_prctl_unknown tracepoint
To: Steven Rostedt <rostedt@goodmis.org>, Andrew Morton <akpm@linux-foundation.org>
Cc: Kees Cook <keescook@chromium.org>, Masami Hiramatsu <mhiramat@kernel.org>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Oleg Nesterov <oleg@redhat.com>, 
	linux-kernel@vger.kernel.org, linux-trace-kernel@vger.kernel.org, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Ujhckukl;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::52e as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Fri, 15 Nov 2024 at 14:27, Steven Rostedt <rostedt@goodmis.org> wrote:
>
> On Fri, 15 Nov 2024 13:00:00 +0100
> Marco Elver <elver@google.com> wrote:
>
> > Steven, unless there are any further objections, would you be able to
> > take this through the tracing tree?
> >
> > Many thanks!
>
> This isn't my file. Trace events usually belong to the subsystems that
> use them. As this adds an event to kernel/sys.c which doesn't really have
> an owner, then I would ask Andrew Morton to take it.

Got it.

Andrew, can you pick this up?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM_94fmQ025diHd9_vKtRxtDbSYaOpfBbshNQYEPQmHZw%40mail.gmail.com.
