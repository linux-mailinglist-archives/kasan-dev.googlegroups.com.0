Return-Path: <kasan-dev+bncBDW2JDUY5AORBFOL4WPAMGQE5QUYS3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id B78BF6835F2
	for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 20:01:42 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id m7-20020a170902db0700b00194bd3c810asf8736335plx.23
        for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 11:01:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675191701; cv=pass;
        d=google.com; s=arc-20160816;
        b=CXmM4ykf56zyENNqOzfgbattMpwpEMLNMwT3856HLHPNHpRPrq2M9R0j5qZH+eEfXW
         LeZZ8XFKyHx9vYSntRlKgrxNaUQ0L5hlfEAA1Bwueuq1GhPUx/vgTi7x8Rv/EP5Xo5BP
         rVE28CTiJU3V0BQNrozW4byo5VQnSPm6HjwXWtxbo4rGcp2QAfroZBbPHD9ukzGwobqO
         Zy8f6x3VygRrQJHoU1o8itBUF6HaU1h54vvsc+f1J4ts/L1odFG9drNTlI7ECQGy5/7b
         WM6zqCsEfkfFwj7I3Z55fyPsMvSclEsgE6+xQ4WDunYHlCFj6tDM+348HE4Oylsx4jA8
         j2Yg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=AabyzxVKlm8CvIMSQ+KCwYlz1Uil2u3dxLCinXH+Xis=;
        b=DRs3io+1cmbWoj5u7WQJ43e2i9QRFxcuVR2w1rTVY+FTnH/HuhyvZENy++6rKjudX/
         60tMW8sHZvCvL1d+WUX+0q5aqMWIKUR1uC/4PFJ9rhH3DhgKebOGh1kknM5Ku6u7A2qr
         +mB010OtQGsGqUdUFCIaH2TmsKrPLSgsKtpCrigi2vTzpML7Ag1Eteoa9PRK9zn/wVsP
         xzX5UQ5qsl/+e963m/UgaeUpgwJ//1cAH81lFgozfZWOQjMpIX3TUYvJHcr8E1CrhkMk
         4abjJG54pjjD9CREV9z1o3Cq8aVcDMWHE7HJDrZK/2TMWNrw27GzBrojtLvtAYsRMDTu
         fUQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=c7mxTGGa;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::42c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=AabyzxVKlm8CvIMSQ+KCwYlz1Uil2u3dxLCinXH+Xis=;
        b=lY/Bdw8i2hP5cf6HK9RrBIoecU7DjUtCswPiZoym0GEphuDgbLxtmOfb9GcJX7BmD9
         noqjjcL/pn6hT+AXSUVBGXIj3ZDR83WEUYt0FjtBgBKcb5xSDV9E3k0R7OpeupjNSO1b
         JXxQOOcuq6h/DOVto44A71v9B4dvtgRnlEJDOqUkM9ihc7d7AljaFJLrrPwkQFHWMsCy
         cGXRrpL8FqIy0c5+x0OUER7jmoEglERGxDYLB+d79Nzzv4/SuI6SPlj729rqO9xwo2bk
         7DX8HucQiPr++zLeZ65oohYRgaDH3OPXzbYMDbaxhBss7ahVDtK2AGWCHdHHC2T3QlTW
         3qVQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=AabyzxVKlm8CvIMSQ+KCwYlz1Uil2u3dxLCinXH+Xis=;
        b=giUrJAi++eEJWFtxh9b8Rlcn6r013zpSL366WGXVedyifxVh1xkmheh1yrrOY6lVai
         McRVOC7x3k3yuQyPrw8dLneLhZVx45iIPpvLcDfzqlnMcino7xbUjb1cB1jA8GYsFDI1
         xzDO7gp1QWZp+ib3yNlO/AYmYXqiNDHAtOUvme1KyEuBE+Y2QuKyYYWj3s/BMnDZL45/
         RjEWp70sCcP5Y/MvJvAna2ii0fNt3hzQm7up4fJdPgz8aCozMcWzZv4Baf2MQLIC4BI4
         kwZ9sYGVuprJ4EbHDWs8DFp7tzTRf2io73tmA4IhbeiK+/YySTPvMGbSM4QylExH25rR
         ynaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=AabyzxVKlm8CvIMSQ+KCwYlz1Uil2u3dxLCinXH+Xis=;
        b=LNx7TYc+UaHWQlaHglphSGdVPKUwKth1UhGWJTygAy/9POEfrm2TWKAgv6Y4BpB9YQ
         e/wK7OH68jtpn6OMgoWBr62plGaqTH+l2vhCyGY9KcUVkGITfdDN5iMfNvwxQGFUVt2l
         scQcAuvPtqD/ZAuyQBCgktX9mfmCz2+0o3p9exTNnfIrAmJ0nOF28UmAIFFMjIy9AOAx
         GxNQ+Suz+IM4DERJsLpoXfJ9tUsM58DkebH2URFtMwzXdFO8PdkXgjr0z7IZA0NdJXdE
         3FuTszLgf9KUnP847gR1X5/YVUP7L/U1XUHpq1jY+QTKcd+AT6/4mmNjXKBII6QQY/a2
         6R4Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kq4t6hlxlWXlzBgIChjtKWLqpedHjr9xX9f3xq8KhkMPOV0GQ6W
	9hy8koW7ojPZevoC6E7Ed3k=
X-Google-Smtp-Source: AMrXdXvQ5GzCRoemEqJScos7NWDub6rXSK5Mw7mIEdncsIfxpy0CMDorbeGdheDxS9KyTxYNsBHEKQ==
X-Received: by 2002:a65:4d4b:0:b0:4d4:18ad:b6b9 with SMTP id j11-20020a654d4b000000b004d418adb6b9mr4231647pgt.51.1675191701388;
        Tue, 31 Jan 2023 11:01:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:8b83:b0:22c:b5fe:a32d with SMTP id
 z3-20020a17090a8b8300b0022cb5fea32dls1212265pjn.1.-pod-preprod-gmail; Tue, 31
 Jan 2023 11:01:40 -0800 (PST)
X-Received: by 2002:a17:90b:3ec2:b0:22c:2166:3eca with SMTP id rm2-20020a17090b3ec200b0022c21663ecamr22226895pjb.6.1675191700398;
        Tue, 31 Jan 2023 11:01:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675191700; cv=none;
        d=google.com; s=arc-20160816;
        b=UG4l6SErs54gpuVpVf+rUCchinKpQjG8JGL0WYOJ9C1Y3gTJyBwS/AajLqROFDcEdO
         8uwea5qPYUb49pISHvYLghVj+Ou4Jt86QvSyCzbanPfvMGKlCmodZBLk4Vyr2m1CvG//
         at5IgdV6QZEcP6T79dfnMB6i802A4dohysA/GuMVfB5lGdxcdOwGRXsxCU6VpH4mms2M
         eQH66NvyHp89+mOfFw3KC+qB6+qznlhJDpYvUNbgmAwcAxlKPc+vceoQbJe0GpOyWfjY
         ohX3Wq70mga6rtkkBZ8d2uC4we98C6XltLq6OIpvdgw4sBOy22yUfwc6S8h80KY1TOuB
         EQwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=JEPpab3psC6bj9jl5RKXgLUqYW14UThmzVF6DuOiw/8=;
        b=0xHOOaDGceIp2bTg244Vq7gPtnfjTL2sngApBMAFCo/qlThBwIJTbDv6X0k5oqhn3Y
         WJrkfUoBUhg6K2zwbqGzeVGYgYZQUve+heCEdTZ12budKxueBo/v2urxbzkFfEn/FVtG
         Sh1iwDlMZmTKhvUOKqLKlsI0giS+vX3rlVHjkQn4lT7hcrWGsWPxx8kUJR0wuzJpCGxw
         DZvkzl4r5D99kDIjiNh+GB3l2O4qkGoFos70asEMVFgH9h6Bz/4W2sF7edj7/sO/vAFU
         yND9DdCN835bZ/baGbjG+jk1vRUUHnqlssIaNBt55AgYgPtsAUuGXu1olaYHFYluR8g8
         dWUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=c7mxTGGa;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::42c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x42c.google.com (mail-pf1-x42c.google.com. [2607:f8b0:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id 23-20020a17090a005700b0022bfa4db15fsi90257pjb.0.2023.01.31.11.01.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 31 Jan 2023 11:01:40 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::42c as permitted sender) client-ip=2607:f8b0:4864:20::42c;
Received: by mail-pf1-x42c.google.com with SMTP id 203so9645935pfx.6
        for <kasan-dev@googlegroups.com>; Tue, 31 Jan 2023 11:01:40 -0800 (PST)
X-Received: by 2002:a62:1dcd:0:b0:592:d71:74ec with SMTP id
 d196-20020a621dcd000000b005920d7174ecmr3537457pfd.43.1675191700062; Tue, 31
 Jan 2023 11:01:40 -0800 (PST)
MIME-Version: 1.0
References: <cover.1675111415.git.andreyknvl@google.com> <4ed1d0828e837e15566a7cfa7688a47006e3f4b3.1675111415.git.andreyknvl@google.com>
 <CAG_fn=V=91XNUyaWuwrgDqNKhHcEQFmD7Q4opc_v4vos+GR3qQ@mail.gmail.com>
In-Reply-To: <CAG_fn=V=91XNUyaWuwrgDqNKhHcEQFmD7Q4opc_v4vos+GR3qQ@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 31 Jan 2023 20:01:29 +0100
Message-ID: <CA+fCnZeWQ7xSTLxLhGmDeyQx6UVDN9J9J0_jUjv3B--dPWaXAw@mail.gmail.com>
Subject: Re: [PATCH 08/18] lib/stackdepot: reorder and annotate global variables
To: Alexander Potapenko <glider@google.com>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=c7mxTGGa;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::42c
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

On Tue, Jan 31, 2023 at 11:43 AM Alexander Potapenko <glider@google.com> wrote:
>
> On Mon, Jan 30, 2023 at 9:50 PM <andrey.konovalov@linux.dev> wrote:
> >
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > Group stack depot global variables by their purpose:
> >
> > 1. Hash table-related variables,
> > 2. Slab-related variables,
> >
> > and add comments.
> >
> > Also clean up comments for hash table-related constants.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Reviewed-by: Alexander Potapenko <glider@google.com>
>
> ...
> > +/* Lock that protects the variables above. */
> > +static DEFINE_RAW_SPINLOCK(depot_lock);
> > +/* Whether the next slab is initialized. */
> > +static int next_slab_inited;
> Might be worth clarifying what happens if there's no next slab (see my
> comment to patch 01).

Will do in v2. Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZeWQ7xSTLxLhGmDeyQx6UVDN9J9J0_jUjv3B--dPWaXAw%40mail.gmail.com.
