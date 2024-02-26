Return-Path: <kasan-dev+bncBC7OD3FKWUERBO4N6OXAMGQEDVATEBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 94C7C867DBD
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Feb 2024 18:13:32 +0100 (CET)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-3652275e581sf28847635ab.3
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Feb 2024 09:13:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708967611; cv=pass;
        d=google.com; s=arc-20160816;
        b=VmndGe3sEGHvQ/G+7daWksII6X3PJIg9yYfhREJzilyCJe2Er9HCDodxUuIzd3fx+6
         pJ4tj/w4aIf/Y+iM0UIVDUbOkC58wbQPlxl6fICst4Mjp/xzpTuJu0PoHI3re2TBWOa0
         BjMQK6PNASdvsxMtIWtncFczxgH3VeMDoojMvw+pwePHPvEss5/Fhw2hNc9FPirXflQJ
         raa2F5kwtOrtK2Aj9D7AZrwHscUiQXTKkXa/8yNLtQqjyTvcMtxtiv241bC/B8nUJ9M0
         brUrz4X+QrOjFX21OsGsLeTsZRM+5N8MjZmHipXXB4j1Z8HHFtKhunpnrqSunN+VSRds
         fqzQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jplDOKl6Yp12GWCm661b/TPxAfwhgr21fQUuzkSI17M=;
        fh=ouatp8qVH0VqCSUaTZioKbhfjsz7qq2S2ULTMgmWTyM=;
        b=y+UeZjox7NEp7Mr1tod5e/87BdJ7zUp0DQFTtguNTMHCZQSDOlbidZmytsBrViBxGe
         AXOewN7HSzXjPmRa+eidRpQ5gsLck5iZgH6GwgohoyKIZNhWO/Q6Kvg/CLYulj6lDhE/
         8GNyutFBALpOxrwBiw+bqR5LcNNpWuZEdPuJI67J9fMd/VC9QUT/ixBDarIwrR2yC7uB
         Tzbus0g/Dz87p02zSsLVDE5t36EhYRCPr6RHe/f17tyA5KEPugEvno9AmE88n30wQ5yV
         P/0baOoWZ0yyXYmAJVqHXxW/VJAkJjXQV+KiYOXEOAgXi9vOArqVpHI/X34mSJF6F9D9
         v4BQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=MywggzII;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1130 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708967611; x=1709572411; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=jplDOKl6Yp12GWCm661b/TPxAfwhgr21fQUuzkSI17M=;
        b=mlE2aUJ64CkmB8y5B53fGTJVv8m7qyenYHloYDDHMMbzw+gU2pCeO5mXK78x5XSDQn
         63V2WCFMlCfhydKdH9s6lFaQu51gLQnQdrMWRL+ZZ+D2me87H2i93SuWzHEsFLoWV+Jf
         YzCmZ7lIxYVzp9Z1ttk/DM0aoTNPt3qKOXBnAZJSw/RwKqIa9uKqylGIuOSMMATHq/uL
         8V0e7BwG38Lxz9sCUN76mlgqf65wj09Saqc2guI+JUK8cabQ9cNT+5NY47xJBjLMc9HL
         sOwktnBnZxaZyH+rsLd80+NxBuD31olWLrubJSigjhx04W5YNALzEp0GS201TgjlKyJw
         11pQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708967611; x=1709572411;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=jplDOKl6Yp12GWCm661b/TPxAfwhgr21fQUuzkSI17M=;
        b=egbysrqTqZLHKtEWBzmRqylwUmmBkCUpo1gAMg7CjkySRD9SdSCsnGVVh8szVB3/OT
         7m62QuZuvPZ1NSKmbyFWIdmNTOEIb0fz7gCHP0md3k5HPILMgZ7GJpgGaF3trNhfso2H
         RwuJbf2/bOWVEHnlAomkUTr4wPdcKFUqU93CEBr15lKIRADKzLN7PADh1U4c3rj2+nST
         UqGCaoCRM2uAtZQmc7pLxU5yQsKhJXwnjq0RIBEhNVry44wE3YNXL9K0UvKIz29Bpvpa
         OhtEk/FL1iuwNeQcbqLnZn6AOprNX8kKraf/UVJlwS29FVyoQvkk1F/dolavnSmHywXG
         xL+Q==
X-Forwarded-Encrypted: i=2; AJvYcCUqWPswcLv4T9vUAP137j/mz8SL3GvUVoVhATNLe7uu4OZheFz8f5D5f0gZGh80Y695CqWKWd5ug/lbc3l+4XDbgWz0p5G3QQ==
X-Gm-Message-State: AOJu0YwQ92NTKyynbmR9M4prVYZvr8ajnCsBm0wdHpnSGIo86AhWnGfv
	OJsu8VPeARC0gSTo80C9G+UfLEbf0i0IlHgLzUQFW7hqigsRsgN6
X-Google-Smtp-Source: AGHT+IHVePEO1YVPGXTSzhh814Snv0dtpUUTAkKCFyrSSm6oLUY/cYOP5HReQc7E1YZ0bUmoWG2pFA==
X-Received: by 2002:a92:da89:0:b0:365:1fef:f3c4 with SMTP id u9-20020a92da89000000b003651feff3c4mr8912060iln.18.1708967611182;
        Mon, 26 Feb 2024 09:13:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:7f10:0:b0:364:f2cd:ef95 with SMTP id a16-20020a927f10000000b00364f2cdef95ls2072757ild.1.-pod-prod-05-us;
 Mon, 26 Feb 2024 09:13:30 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV+4BgM8dH7tHZnNaXDd9FubdoNKSH2C+ntM5D1XJEap98OdL7bT0Rr76tMjPiynGKEV5s5yLmbo73QwG3P9ZtyGPCVUDD/0lpPEg==
X-Received: by 2002:a92:dcce:0:b0:365:75b2:a338 with SMTP id b14-20020a92dcce000000b0036575b2a338mr7926984ilr.24.1708967610479;
        Mon, 26 Feb 2024 09:13:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708967610; cv=none;
        d=google.com; s=arc-20160816;
        b=A/kz7PCAOvFqG9q6PuvIbu0robY4YCjPw7yoLz9yUeKp4hhXz2bUdY3F+drIOkovD+
         5/+Dfrw6RdwqysfObYPvfThAo9TtGIY/9XAXtkH8VgZ+5aB7/ywx0351gpUraIEF3o8U
         x9QF4QtEJH7dtwRVFCVtVw0IY4M6ovPpsepklAcLo0SmCKSMzsXiGWrP/xp+eLeAejG+
         hmwphwzIBZxTO0RDOBthDdl/1xeSCGdhvvSsRnUL/Ywk1Wsi+zDZrhjW1ROzpZwJYjrz
         7eoMaBr0DzO/M+tqjZZ4o+P/sm4Xr31T7N8ZRxYyVfKCPP/yrvtOo75dmJDjLjTaXog4
         dqtQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=EyV42V4YwospafBlBP85zlF0CzzIrV0ckGMLg38+cps=;
        fh=de4PuobNlKzt7xzSJ6An8WRCum2yGzjSBqa0PhaQsw0=;
        b=wacN9g65SAFlRiEy/Jo6Ehi7gR1eYn9t9q1tq7zgx9+ySEoIc9H/gkbqWrOiNGi3D9
         X/dq+y4Ry/mjD0pcj6yw6SnMlxTYvAwWrOzZYICY7iJDTWlDol9nZBVzoqtr0HbpAXkU
         5aB47q1BLD60F2sILvIkmJRYjiDABY5O1RE0ZVgh7OrHKFS5yosxh78HHsCbZIN4mdJJ
         yyyJKbePvmeQRN5aEi1d/FpH96qJPtFQeDmcBXVHPKrJ5p5V0pzJQpjFF2wYvU66kS+d
         FWaL9eNdckdFm/BfyXpewb2iXsnclQmqswEKV44Ww4b/VoGUSqqy2J9K162NHCZM6js2
         rzAQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=MywggzII;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1130 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1130.google.com (mail-yw1-x1130.google.com. [2607:f8b0:4864:20::1130])
        by gmr-mx.google.com with ESMTPS id r206-20020a632bd7000000b005dc1683daa5si468199pgr.4.2024.02.26.09.13.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 26 Feb 2024 09:13:30 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1130 as permitted sender) client-ip=2607:f8b0:4864:20::1130;
Received: by mail-yw1-x1130.google.com with SMTP id 00721157ae682-6087d1355fcso18240217b3.0
        for <kasan-dev@googlegroups.com>; Mon, 26 Feb 2024 09:13:30 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCU9hgYJdShmU2YGMgq5OB7ONzGgx/I/9hMkZVNYkyELK9E7A2vPI3jFd8VtJFchmgeWlKCKN9PHZIlH6HdOdb31UYrGr020RymB1Q==
X-Received: by 2002:a05:6902:210e:b0:dcd:1f17:aaea with SMTP id
 dk14-20020a056902210e00b00dcd1f17aaeamr6639276ybb.26.1708967608014; Mon, 26
 Feb 2024 09:13:28 -0800 (PST)
MIME-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com> <20240221194052.927623-14-surenb@google.com>
 <a9ebb623-298d-4acf-bdd5-0025ccb70148@suse.cz>
In-Reply-To: <a9ebb623-298d-4acf-bdd5-0025ccb70148@suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 26 Feb 2024 09:13:17 -0800
Message-ID: <CAJuCfpE6sJa2oHE2HrXAYuMeHd8JWd0deWa062teUs3bBRi2PA@mail.gmail.com>
Subject: Re: [PATCH v4 13/36] lib: prevent module unloading if memory is not freed
To: Vlastimil Babka <vbabka@suse.cz>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	iommu@lists.linux.dev, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=MywggzII;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1130
 as permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

On Mon, Feb 26, 2024 at 8:58=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> On 2/21/24 20:40, Suren Baghdasaryan wrote:
> > Skip freeing module's data section if there are non-zero allocation tag=
s
> > because otherwise, once these allocations are freed, the access to thei=
r
> > code tag would cause UAF.
> >
> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
>
> I know that module unloading was never considered really supported etc.
> But should we printk something so the admin knows why it didn't unload, a=
nd
> can go check those outstanding allocations?

Yes, that sounds reasonable. I'll add a pr_warn() in the next version.
Thanks!

>
> --
> To unsubscribe from this group and stop receiving emails from it, send an=
 email to kernel-team+unsubscribe@android.com.
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpE6sJa2oHE2HrXAYuMeHd8JWd0deWa062teUs3bBRi2PA%40mail.gmail.=
com.
