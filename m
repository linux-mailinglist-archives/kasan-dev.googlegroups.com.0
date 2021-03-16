Return-Path: <kasan-dev+bncBD66N3MZ6ALRB7PBYOBAMGQEP6CWD7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id CF3C333DB8A
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Mar 2021 18:55:10 +0100 (CET)
Received: by mail-pf1-x440.google.com with SMTP id x8sf20621199pfm.9
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Mar 2021 10:55:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1615917309; cv=pass;
        d=google.com; s=arc-20160816;
        b=dJcnT6kf2fJghvF8lzZ49y0sVqXcH7NBdIUNc5eJVLKZE08plFo0dgYhOq5qpMh2LX
         dqIzRNkwSdm6Vmg2cZkPwNUhft5BairxtxYq7fZYNi1qG1qTuPSj/X6NJHgIqa7Ec1AG
         1rKe1w+4oZK5Ly5bT6jWWZXm3w4l42wMwWxlfqIzySUdcWORfByNW/pRvmgfhIRm2YMU
         rxRuDdiswsAUSfUfgioN8FPvLAQSZZaFRGL52PYQkjhc+shfbhKa4my0B6Mz5wzIgvLL
         dPoE0IiOsLJRyBD+u+tpGsvUg2heQa1DcjF/wYWCjwhbpWv3tEhfWGpWq2pwDl8lRh64
         r5ig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=ONeDdb5RjojMSEZTagPYM3yDVQQX5oRbKbhEeDgwvW4=;
        b=Vhj6QRPmkccmygVevZ65gNdTQWP6dQRlSeC7CZzwYFdA+0BOtlLrMuxlhTJ9mdrm0f
         uV17MTJG2CYCyNEzoRJSKPBrlFpLAh92S6ZywXG7FxEmkmOU2zDtbQqOAP2YXfpK9NVc
         6GUVKwveySfIJTGjaB7R81ksXGOE/aD9RPfQWaGk/WAfCtmYJNoZR16kqu5ifV5LyteP
         TyXItyf91oBXiFwd4x2/orWviiMKi3bM7JFr7Fylv3Nln5RakbXBWi5Vg+drY6yLeBAg
         QEKNGih/Zprc6HiFnYcHh3cyWjRTaPo9LOyodl6zXiP1dV34TyO1VLE4XiPRqTaZxsiJ
         ya7w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=dRepZzYg;
       spf=pass (google.com: domain of oleg@redhat.com designates 216.205.24.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ONeDdb5RjojMSEZTagPYM3yDVQQX5oRbKbhEeDgwvW4=;
        b=n1At0PoKd7JCnCg+VbDYCuanqUlRdHw51CnyTcfqE63VypxEhJvCB2+RL/iEJn5YKc
         1tCBxswDqcBNMwaDvc+lXlgNRf7WNjvXGzNr4frjEdw8xCnc9tcIxkQkGP/TUv9pUxDL
         n8nueuzCoXklDhRjzEmgHVk5iUb6TVr4Ozgqc9PkcDeNnnqf7qzGRdHVPVttmtO5Atxc
         hFRoxlmmxqyDy3l9rSpZAoXK7EmmXEnlm7PxU9erm6cnZyPsV/h5Y4FX2b80j3dZj2ew
         JTtWnWJ+UQtIvnPuTVCyz1m3asqxCIb3z15xZoe5H0qtDknPE7c8dwheS1Ruo9vblgH3
         mYug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ONeDdb5RjojMSEZTagPYM3yDVQQX5oRbKbhEeDgwvW4=;
        b=WxYpT/ndsW+fl22Pm2jl9jkyRENnYZ3QycGABSCzfy1o/Hg2qHLX+izD8KgW1fmgaD
         s4IMbrcgc2VEww9wzcH6pdAVttWVxDsmF/uV41uTWcvtFH1MdMYodDsB0QgHUlgtUo1k
         uNgBVwMA3Dmc6DCY25nyWzYo/8Qq6V8TaENHfVD9roGdexem3E+hUpx8AmgKDDOYpuYL
         drSlcz+GZUg7EOgcx3VAE21+k6LTWAbo/t/ruohqYi4Ex5KvXtMxcFjeZas49p9yPrJ8
         LMKStrOp2IBE4pG5Ap61jBU+7hZQZ6tEGQosjGVPbhy16f1XkbhHpHW7coYINg+WaUWG
         t37w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532lItvEO1RGHnSEnaqACWDT1ZayyIWikx8AttdpO2W8ghag8AH8
	Cj0va6aPLpox2GL4mLYakWg=
X-Google-Smtp-Source: ABdhPJwizMC5P6tnP7rD5cLi6jroefbvggHlPokp0dJzEcvMcI5Yu1wsZbpwGbPLrFq+0+1YuTBMdQ==
X-Received: by 2002:a63:5c3:: with SMTP id 186mr706609pgf.173.1615917309593;
        Tue, 16 Mar 2021 10:55:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:31cc:: with SMTP id v12ls10828108ple.9.gmail; Tue,
 16 Mar 2021 10:55:09 -0700 (PDT)
X-Received: by 2002:a17:90a:be09:: with SMTP id a9mr211850pjs.219.1615917309022;
        Tue, 16 Mar 2021 10:55:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1615917309; cv=none;
        d=google.com; s=arc-20160816;
        b=W75IqiH1urJxag1O2T9FUdK1yxZNl2FFtDOL+vg0tg5ScBoCh5gyO80egPn7Qrsb4v
         QKKbRYNErKoTAho6R4OcomLwIidlJ9DVL2si2Csy/9FA8lwEKMbSQ/5Lsinv35RI1NEO
         2TerhfWmlsw8jXw86z/B3C66CcdP8L/iv97L8/9Z1UfBYvgatN/pbg1TyUmacqERAJbr
         fpw97NTpMMHsKB3ZWxPfN9yo+dilxRrk4q3FHPs3WyQKYblDOvUJSPHxLd5TdI9hdy/G
         YKiS1ogjEjXOa2xnlqWUti0uF1F2i0EVX77RiYSy+mv4d6W3s8RM8fFCpmmJo+6Ct8ry
         ajGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=et+8M4fnfpbY0GeGG05MXy/pGLb3+RZRFKGCfdaC3Sc=;
        b=Ru2zvOkQFyvnJ5XYOvmhpcu5Udi4qCINh86LMBnS84zfgeHMD8/2Pd0h0IMbHrvbNk
         Jczj6FbRYo+WxuGX2cxoY7Bov28BfoaUUuyjBv0qkUV43dLzgbCCQXwIol5wiuWZ3epy
         7ol6vLVPWbtlgxh/W0EuBiyiFzGsO+bmhuSMYS54ZeA3wuCrNNkX6B1hELQgElKOhgdU
         zIYg3ugctrOMjYsUdNZp7iC2uaw3lTQo/YE7bYMpdwf2Qxm+yywmpGymtZ+yVWjST1gS
         0r/zD5XoufgZp1s4fmzokGLymjc67u9DbIwai4hVDPhA5popQBZn/2vUmKBvqp/5HmIy
         6glw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=dRepZzYg;
       spf=pass (google.com: domain of oleg@redhat.com designates 216.205.24.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [216.205.24.124])
        by gmr-mx.google.com with ESMTPS id e4si1519205pge.1.2021.03.16.10.55.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 Mar 2021 10:55:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of oleg@redhat.com designates 216.205.24.124 as permitted sender) client-ip=216.205.24.124;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-525-X_-hKvDyOCOief-DATOHdQ-1; Tue, 16 Mar 2021 13:55:03 -0400
X-MC-Unique: X_-hKvDyOCOief-DATOHdQ-1
Received: from smtp.corp.redhat.com (int-mx04.intmail.prod.int.phx2.redhat.com [10.5.11.14])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id 2E413760C7;
	Tue, 16 Mar 2021 17:55:01 +0000 (UTC)
Received: from dhcp-27-174.brq.redhat.com (unknown [10.40.192.135])
	by smtp.corp.redhat.com (Postfix) with SMTP id 744255D9C0;
	Tue, 16 Mar 2021 17:54:57 +0000 (UTC)
Received: by dhcp-27-174.brq.redhat.com (nbSMTP-1.00) for uid 1000
	oleg@redhat.com; Tue, 16 Mar 2021 18:55:00 +0100 (CET)
Date: Tue, 16 Mar 2021 18:54:56 +0100
From: Oleg Nesterov <oleg@redhat.com>
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Matthias Brugger <matthias.bgg@gmail.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Jens Axboe <axboe@kernel.dk>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	wsd_upstream <wsd_upstream@mediatek.com>,
	linux-mediatek@lists.infradead.org
Subject: Re: [PATCH v2] task_work: kasan: record task_work_add() call stack
Message-ID: <20210316175455.GA25881@redhat.com>
References: <20210316024410.19967-1-walter-zh.wu@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210316024410.19967-1-walter-zh.wu@mediatek.com>
User-Agent: Mutt/1.5.24 (2015-08-30)
X-Scanned-By: MIMEDefang 2.79 on 10.5.11.14
X-Original-Sender: oleg@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=dRepZzYg;
       spf=pass (google.com: domain of oleg@redhat.com designates
 216.205.24.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On 03/16, Walter Wu wrote:
>
> --- a/kernel/task_work.c
> +++ b/kernel/task_work.c
> @@ -34,6 +34,9 @@ int task_work_add(struct task_struct *task, struct callback_head *work,
>  {
>  	struct callback_head *head;
>
> +	/* record the work call stack in order to print it in KASAN reports */
> +	kasan_record_aux_stack(work);
> +
>  	do {
>  		head = READ_ONCE(task->task_works);
>  		if (unlikely(head == &work_exited))

Acked-by: Oleg Nesterov <oleg@redhat.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210316175455.GA25881%40redhat.com.
