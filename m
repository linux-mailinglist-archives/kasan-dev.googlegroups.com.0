Return-Path: <kasan-dev+bncBCMIZB7QWENRB6OQ4X7QKGQEMACWFPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5A2482EFE98
	for <lists+kasan-dev@lfdr.de>; Sat,  9 Jan 2021 09:25:31 +0100 (CET)
Received: by mail-pl1-x63b.google.com with SMTP id l11sf7660506plt.2
        for <lists+kasan-dev@lfdr.de>; Sat, 09 Jan 2021 00:25:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610180730; cv=pass;
        d=google.com; s=arc-20160816;
        b=JEOklOW7VV8UD+/qR3C8opet5MGOt4GZkLjaf6TN5X4cs+GBOruaCZF0XnydKvZyeD
         YbvFxSVE+eXKw/1IjPPCPXhHaPT/ApE05ebB1kuZv2vgX+SL/VOsJQR8C1wWEP3FO7fL
         AQXxf9CL4545g9eigo6rlNjS6G6habuZDKAHOiH3/EBE0rtWZ7lXmSlpm5bgMCJQxaIr
         JIHz1iVdpTAkLx2FX1ZJf0oaxKm/rw06hn2h5cNQN8TRwshuGpLh6TUi+K0Lj2zCgAPh
         T+eM4Vl+d6kd2Lx516py2aMq6t/H0xucTFdfzK5ZnRpVa0IOtQTmPk+2+9aneAtKjtKq
         +ySg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=5Q0kie0oYDXG7/WlS/gTKvSCAq89lBzNiiXJDLw2GHg=;
        b=hRF9KiqyBtgn4gFmQVueR4H97knYkeOhpJ9yYgQwXyV0EG8toCohhy3964KRNQnxTR
         TIeYO3hjqjlX/2usNCl/ENOL6Vb5xYzrlJOxVlRpXJSgljhYzoxLb3oy5UQA9Kw0cV/H
         yG9ry2qbcvlMW7h9Iscx2Q9n871m7kDrctpV4tYqQD2SIgNNOsy97YWip/Vbnl6oJojS
         8EH9K6YOLOd49LLmKp/ygpta5DLIeJrcYPxlJaGZPrzX0e6Hu3HZ2X9xsjcdT2xrBWMh
         dWfKyYOTndQ9MhqO+jnsIr38AIPiFbrsd083MirUXr2bxlyiU9Vq55Xz/WUzE6/rZN8k
         7EcQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=r2nk91PG;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::832 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5Q0kie0oYDXG7/WlS/gTKvSCAq89lBzNiiXJDLw2GHg=;
        b=nFk4O49bePaPNy10JW6JoOvIoryrxvLUwDVg1Y8VrXEp3m2LOTmSa56AFtx6hhkAoJ
         GwSiTHlmxJ5gqPavj58SIaCVQbD+TRnLh/MtJA4stwWzBZgXE3pPh0vA+Vojhbbf5OdR
         flFwUWFgv7aO1S1a5yukV3tQd1YqgUYFb8ntEi98VLGsbbRZIrATHx70DC7eb0w27TN9
         o/9TgB5lblP1vZnqGBgvmo8hsghHwjWqenJCutPK5UVEl2H3SwgvjFOOgg3pOSEE6y1V
         TxKmZUcTiKbZYuMcF42kerCqPYdSDcblWSyop7EXuM4ODaooGHtmHRRTErgVPRYwFvPj
         nWnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5Q0kie0oYDXG7/WlS/gTKvSCAq89lBzNiiXJDLw2GHg=;
        b=TBJ+DfAy9O6Q0dtt7PazwUKpZo9jG7ZQrnS/YQugBjUfSIRV6Y5cC1fGypo4ZFwT2F
         BjXlOMeOJafFX4Iud/CDrRj7iO1LN7FfxA6qRKoJEzGESdKdNseN4fW8L7Ikk3BPggC6
         KnnHm/eGjyMo+QuYeGqPnD975j8hAbt5x6gscjL9B33P6bjLy8VfmVoNd53eJul1kvWs
         jJKZYmO9ALwVu4EIcIEGmAhMAstfD6ctGPxP/7JAnklS9uKfarII7Y1enuwZL1Rm1NOA
         B7l4YFKI4Mx+3AGBa1P9zmzqMfLAjp8FtIlgtapnilfO5go7dSIuUZ+RuGvpltwz92FA
         vjJA==
X-Gm-Message-State: AOAM531EGmluVjSaSJPcjKoJ6TW2zT9CNupTf9msyctDzQ9XRAuQccBy
	yNVReXPKrkrjAGcaOY7leWA=
X-Google-Smtp-Source: ABdhPJyA3O34eDmiiH67YaUzjNDQ3OG2RjNThmTBbb77/r5VjwIEJOALiEEvIrUf2MKsmPmRpiwG7Q==
X-Received: by 2002:a63:af50:: with SMTP id s16mr10858192pgo.448.1610180729882;
        Sat, 09 Jan 2021 00:25:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d713:: with SMTP id w19ls5914561ply.1.gmail; Sat, 09
 Jan 2021 00:25:29 -0800 (PST)
X-Received: by 2002:a17:90a:5b06:: with SMTP id o6mr7926696pji.49.1610180729365;
        Sat, 09 Jan 2021 00:25:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610180729; cv=none;
        d=google.com; s=arc-20160816;
        b=aSkcXYS9I9PjfUI4S3l5SbJKMlAWuLp/vCxyRqaGkNW0t2/UHVaWK6E3tK8/Tmj+83
         ron9QfyuxEic12y1VrOsPa04rYKARZQsOWKtZusbZ9MutXqBWl2hM/pLhPjYXpI9uwqU
         1RqKx3EkNgAGbHsqPIvlJ9h4D3sU6DzQwUyU+fv9WHW+RgUCyjGf6ej0By4pIvkgO6lJ
         dNxW0VTOIb4hA//Pe7/DXewXeHaWnno1a8tEEfjqK5TavFL/HuRqO7/3ZREGdePUCRFe
         NSLpLv5Pp7KHr0jXSSDnwvd90d7VjQkeb9mdktv6Oy3K3cPg+4stwdGsPmsGk9B8ukF0
         mY1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=rm97YJi5z7aT2GM3LaGXW3512xKi7esx9Rde6EaNLB0=;
        b=OSWVtclpIiptokeLcFS4zDLaIA+s9z+72pGBkCcGlaYQceiOk8v62aiKjmM8kmxQTF
         MaT067yiu4UQxoPOssy3F1hzvYovFSMyQ6U3cKWLeQLHxAwlpeLJnKivs1j3ViYe/2cF
         RJkNilqiwHiXqbKGTO+oNGWffYPbtHotGrDRzw0pVnY5bBPp3TcTqRrpF50+Vueh83og
         WFnr7Issd+DUNulmf/qXwNGjWnGbPSCy2+cvCBipil7OECfqdZLAE0OlfOClWptm7fwR
         8rAY3SciJbR0GLSxKTX30Ai+h5GnVoGuUqaSXDeDVEvUNSmjCpWhovMIzo+sv5yD+xP8
         fyeg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=r2nk91PG;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::832 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x832.google.com (mail-qt1-x832.google.com. [2607:f8b0:4864:20::832])
        by gmr-mx.google.com with ESMTPS id e193si790280pfh.2.2021.01.09.00.25.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 09 Jan 2021 00:25:29 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::832 as permitted sender) client-ip=2607:f8b0:4864:20::832;
Received: by mail-qt1-x832.google.com with SMTP id z3so8195100qtw.9
        for <kasan-dev@googlegroups.com>; Sat, 09 Jan 2021 00:25:29 -0800 (PST)
X-Received: by 2002:aed:2f06:: with SMTP id l6mr7184486qtd.66.1610180728484;
 Sat, 09 Jan 2021 00:25:28 -0800 (PST)
MIME-Version: 1.0
References: <CACV+narOjL5_o_in_WtOo9kjhcKFD4S4ozctPtdj6JR0+b8adg@mail.gmail.com>
In-Reply-To: <CACV+narOjL5_o_in_WtOo9kjhcKFD4S4ozctPtdj6JR0+b8adg@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 9 Jan 2021 09:25:17 +0100
Message-ID: <CACT4Y+aAarvX0aoesAZjfTnHijwcg68G7o-mtV2CED5PgwygZQ@mail.gmail.com>
Subject: Re: KCSAN how to use
To: Jin Huang <andy.jinhuang@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, "Paul E. McKenney" <paulmck@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=r2nk91PG;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::832
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Sat, Jan 9, 2021 at 6:11 AM Jin Huang <andy.jinhuang@gmail.com> wrote:
>
> Hi,
> My name is Jin Huang, a graduate student at TAMU. I am interested in KCSAN.
> I want to ask is there any hands-on instructions/introductions about how to run KCSAN on Linux Kernel?
> According to the official document, I compiled the 5.10.5 kernel with  Clang11 and CONFIG_KCSAN=y, but after I runned it on QEMU, I did not see any information about KCSAN in the dmesg info.
> Is it the correct way to try KCSAN on Linux Kernel, or any instructions?

Hi Jin,

The documentation is available at:
https://www.kernel.org/doc/html/latest/dev-tools/kcsan.html
But enabling CONFIG_KCSAN should be enough.

When booting the kernel you should see this "kcsan: enabled early"
message on the console if you have info level enabled:
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/kernel/kcsan/core.c#n652

You may enable CONFIG_KCSAN_DEBUG and then you should also see these
messages periodically:
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/kernel/kcsan/core.c#n490

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaAarvX0aoesAZjfTnHijwcg68G7o-mtV2CED5PgwygZQ%40mail.gmail.com.
