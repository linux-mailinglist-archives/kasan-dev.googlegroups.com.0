Return-Path: <kasan-dev+bncBCAJFDXE4QGBBU7VTW2QMGQELITFG5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 32F7993F3CD
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Jul 2024 13:19:49 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-52eff760f37sf4223290e87.0
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Jul 2024 04:19:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722251988; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZJm6mFHeXXgjvxPKFCHJZN0vdZDxJj2d8P5P0P4LMf9PqSu6N5/AgpuBDVBEztmVoz
         LPfgbaDrZXAjmxTjV4u+qUoJQ8L7+CWm6J2RNPtxnGnwvVz+XvqbSbIUeaSAoEcfAd0A
         WT7siu1XhCEg2lLmEbQgTW2uVuQ15sDgDiaZOzN2TQHxBHx+gTXM0/9SDF5MQx+7DDAW
         GwbVG6clQmoER8AvVYpmtLIQhsqszFiuIaNIsjr8imDX2RI+xnPSnancIyE9kW+mtnaL
         QmDwdC5JwsXAzyyDs5WDFHkovv93Zedm1K6/BH1PCRJnLdxMsOW/EYZoVrHdvnZ9a6W/
         6Bwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=3WqhUDhaCkLTWqeVIWrwk8erLyl8nGxFsydUL1YfEfA=;
        fh=mJX8Z83ld4/n9KyX7/oEN4BmXZZ1ieTs9noI+47+GII=;
        b=NM+qkwxYDh8HpeE6pR/WrcggS4NA9SxQdIHWw/bDxEbCArNThCPvFOzpk1zldxKquJ
         sOfzw0sV9Y+RWA5QKOqHI7i5ylEZmmber3w50eVST/CJ51cJaEuZw4KmCNS21IpLScWy
         lO3dttys/KMXrWRdjMZCaB7hy855rX118eJrKrJ5QKcG13Ljmn0zs/ESDP6O5fEDN7zq
         zv1s//viV4cXeHz+I217wu+ghLUWQCgXIRO+jPOUlBJHs++umFXS0ttTA7oAffrnZFSM
         NwQS3EW5uAPhGj4Ks9xowEarwpfr+httRF4aG9pAFN4B8V3Xs1R5LcxdaGAjbigrRMaW
         T/AQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=GdbYdrqT;
       spf=pass (google.com: domain of adrianhuang0701@gmail.com designates 2a00:1450:4864:20::529 as permitted sender) smtp.mailfrom=adrianhuang0701@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722251988; x=1722856788; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=3WqhUDhaCkLTWqeVIWrwk8erLyl8nGxFsydUL1YfEfA=;
        b=Ulf8ywE7YSYJy6bcL5iDCKz/Wzq7J3Q+pMA4eIchkJ0d++qR0JYWIbywBsmpMniRk5
         2NzeVZwOa1qHOFMkVua18fGITDKmzMwLRPBOP6BjJ3QdEpJyaoACcDOpPGed+kn3XlQW
         JbQnjjSK+UsNqSfF111XyzhQDvNy9OXy/kMsLdiwjGi86I4eS1ySENEn6hwlpNx6AV8I
         6kHwkvqI8R93B9nKNxmY45WpFWHokZdSLhYRmwEj3K3LF3z55imgMTnCo5z1PznNrJiz
         7Q+/uTbuLrgJHUtCCxIm8/sZ7B6YMHF9yrbaKNhTnTb2i9wxD7qiNVK7IF8O0yfZq0C6
         eirA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1722251988; x=1722856788; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=3WqhUDhaCkLTWqeVIWrwk8erLyl8nGxFsydUL1YfEfA=;
        b=BPWffoju/v6SeqH/ehDdkjO79n2OSD3/PywITWACBZ1CHC1Pv3UeRi4yKNMK3+Fi1d
         1hSYqkSokgxQx6o26A7Gv2RXwMiL67pDE/WkF+Bw5v+7px9ga72HDz9BeeQYUXhNNRk7
         XBwrRFuIwNn+k4EfU0n9gMxKCJqs9aCS2oimxkR30OAx5VvYMNMxqVpwCs+wwjB8ZpWl
         9hVgskhHc5R85x/IMbjGRSmo0r7colat1oRavhoYIE7MtoI3lXpxfGd9g2nsNmEtGFL8
         jmBLIyHkj1GdpgKI2fxLWrw7WL4rbKPbRVPNEgFYFVeZtaA5UCCjkGJbtuvvM3Z1jE9Q
         BeQg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722251988; x=1722856788;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=3WqhUDhaCkLTWqeVIWrwk8erLyl8nGxFsydUL1YfEfA=;
        b=GhJuGLFQCK9MuGKJb1qKa/KyQClzGtsD0B7JTkZBulitmRUVrv4E4W8Ry6T/a9AIj5
         tMC6fofKY3984lUIq5LHxTg/l0yrbLyDUvrkCY7IqRiqBHj3T4R+LTbRcd5Uo8X47/oV
         zG9GWF7d8sQgCWDT158r+Vs9+QF6sGpFpLLPcpYVuRB5GliD1DXw6UORn8kgGHaNf7tA
         9e8ysq2NjwE0vzS5bVdj8B9Aw78FOnWGwRHWD9siMISKp+hjuUi2xsnbNDdagAPhIcKz
         TkTn4SdEp5CpWmi0GPEo/A1zt6bT+2gMqVQ0opTkdgX6VI9x9KN19G4lY3vplcJRvPEh
         gsPQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUNhXrjwdGT4RNikeUQf1vjUfbcGWMvGCJNcWa8LWe/IxpZgYx0PdUtluAbnjROYpUKxnCHEwVcJq43m/ssW7ci+WKGpMiWRw==
X-Gm-Message-State: AOJu0Yw9QeWZB/logzjJZx6q7so6wTYsuEgDIw347pB9PWt+ADQ8LIym
	3fP7YPu5yQyY+i8KmrOWCIwK9uq/6F8HoFYvfsFBkujvhqlAX+QB
X-Google-Smtp-Source: AGHT+IE9z6IUDMSPIizUjPpRD2U6h5QWcspgHjZLrIkwqWA2dc6n7Qgz5lWs6Bla6FmHniDENnPYUg==
X-Received: by 2002:a05:6512:3299:b0:52c:d78b:d0b8 with SMTP id 2adb3069b0e04-5309b2c2aa2mr4331623e87.39.1722251988039;
        Mon, 29 Jul 2024 04:19:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:132a:b0:52e:d12c:cf91 with SMTP id
 2adb3069b0e04-52fd4231834ls1744177e87.2.-pod-prod-02-eu; Mon, 29 Jul 2024
 04:19:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW6OzqvT+Wnp0OWf6hGN/4PQJ0+bt1O2kTesOMCS/+ryzAfK51n7vWn0aWUL/7CtTXNdJ/RHVCRRAA9XG8wswgWQ7KYJkMOJoUTXw==
X-Received: by 2002:a05:6512:250e:b0:52c:e1e1:ae91 with SMTP id 2adb3069b0e04-5309b2696ebmr6998099e87.11.1722251986051;
        Mon, 29 Jul 2024 04:19:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722251986; cv=none;
        d=google.com; s=arc-20160816;
        b=iJho/9SVZlW9ELeVnrm6r4qMpTxtivFq8NnVIJ2xHLTpSp/E8LV7bIulUq2+LFW7Zy
         HJyTdBf8jUUwlBgNm9hTnG+MBqwFcDYxbhPChGcIXotjCSQXG7jNtcwhRLPx6BI006ZL
         o+jGg7QXRpmvj3Nq9AYiik23Lgy6tZhQVkbKmgyCHEMBzYPW3exJMvsBpXKcg900XZvV
         EDKl6+SMI35TY/Xiu9ydx8N5KjdzV/kgdQ/B8aUmA0O0vmnTzZ1yvNhVssFUm+p8OXx6
         2vKlOmz2YJAiiPGi7yku2MwglEsiYV5GbYDN1WhhTzbzhxGdhw/7zxk0B1CcZIldHN3V
         F3EQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=7ZMoS+Oc1qXkku/9gbvh835GC/MRuyc4+0P4p5raWYs=;
        fh=oKquF+1zj+E2QMM9bQ2nfer7I39GOr2aBntEoDq6HAU=;
        b=Q3/dvvCVRPwnSCel4uMB50g6UYFke34gOXevl+flKN9Pl79k51zb3yaQdckbZLknDs
         A+/zok2X3xLNoS5Lj3Ovbp0TjcA9FAFHogF9k4O85Ul0PX8/9t2f3FDqWbtBDG9RgrCD
         SgDMnPFBQZSC4lrzAkiGA5t6E6gSpHEITuqsS6LHUcSHZL3RZ3L+z7qoQQJqYhK5Ydhx
         tXgNwQ2P5SvI0sagofniW1YA8NwpdnPB0HZRRNeMONl+cFYP7C/LKNoUcmZ2jcuWGbnb
         DAK65PBf1nZB24rSrrlUkqeEIrD98Pub+wo1JFB5KzGU/tklgFCTYdiRnwHTPSRg9Ihp
         Hx8w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=GdbYdrqT;
       spf=pass (google.com: domain of adrianhuang0701@gmail.com designates 2a00:1450:4864:20::529 as permitted sender) smtp.mailfrom=adrianhuang0701@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x529.google.com (mail-ed1-x529.google.com. [2a00:1450:4864:20::529])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-52fd5b9e382si377428e87.7.2024.07.29.04.19.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Jul 2024 04:19:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of adrianhuang0701@gmail.com designates 2a00:1450:4864:20::529 as permitted sender) client-ip=2a00:1450:4864:20::529;
Received: by mail-ed1-x529.google.com with SMTP id 4fb4d7f45d1cf-59589a9be92so5188186a12.2
        for <kasan-dev@googlegroups.com>; Mon, 29 Jul 2024 04:19:46 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUanOa/87YNTVfBTUvu4UyJpCarXusWt7AsFueysTjNIQE45Y82O2zyqftU+FVGjErm69MUF8xL5wlLFUkbUWaDjDoxWh/h5QAVhg==
X-Received: by 2002:a50:871b:0:b0:5a1:7570:8902 with SMTP id
 4fb4d7f45d1cf-5b020bc19cdmr4619855a12.18.1722251985028; Mon, 29 Jul 2024
 04:19:45 -0700 (PDT)
MIME-Version: 1.0
References: <20240726165246.31326-1-ahuang12@lenovo.com> <ZqdTK+i9fH/hxB2A@MiWiFi-R3L-srv>
In-Reply-To: <ZqdTK+i9fH/hxB2A@MiWiFi-R3L-srv>
From: Huang Adrian <adrianhuang0701@gmail.com>
Date: Mon, 29 Jul 2024 19:19:33 +0800
Message-ID: <CAHKZfL3YsfSLfNq268p+bikzgwvj+Ng7R09cZQk16aKio3fViw@mail.gmail.com>
Subject: Re: [PATCH 1/1] mm/vmalloc: Combine all TLB flush operations of KASAN
 shadow virtual address into one operation
To: Baoquan He <bhe@redhat.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Uladzislau Rezki <urezki@gmail.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Christoph Hellwig <hch@infradead.org>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Adrian Huang <ahuang12@lenovo.com>, Jiwei Sun <sunjw10@lenovo.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: AdrianHuang0701@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=GdbYdrqT;       spf=pass
 (google.com: domain of adrianhuang0701@gmail.com designates
 2a00:1450:4864:20::529 as permitted sender) smtp.mailfrom=adrianhuang0701@gmail.com;
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

On Mon, Jul 29, 2024 at 4:30=E2=80=AFPM Baoquan He <bhe@redhat.com> wrote:
>
> On 07/27/24 at 12:52am, Adrian Huang wrote:
> ......
> > If we combine all TLB flush operations of the KASAN shadow virtual
> > address into one operation in the call path
> > 'purge_vmap_node()->kasan_release_vmalloc()', the running time of
> > drain_vmap_area_work() can be saved greatly. The idea is from the
> > flush_tlb_kernel_range() call in __purge_vmap_area_lazy(). And, the
> > soft lockup won't not be triggered.
>               ~~~~~~~~~~~
>                typo

Oh, my fat-finger. Thanks for pointing it out.

I saw that Andrew already added this patch to his mm branch. Let me
know if I need to send the v2 version to fix this typo. (Depend on
Andew's decision)

-- Adrian

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAHKZfL3YsfSLfNq268p%2Bbikzgwvj%2BNg7R09cZQk16aKio3fViw%40mail.gm=
ail.com.
