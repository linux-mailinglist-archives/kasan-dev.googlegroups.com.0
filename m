Return-Path: <kasan-dev+bncBCMIZB7QWENRBHGPSKFAMGQEHM5WFLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23b.google.com (mail-oi1-x23b.google.com [IPv6:2607:f8b0:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8495040FA3D
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Sep 2021 16:35:09 +0200 (CEST)
Received: by mail-oi1-x23b.google.com with SMTP id v24-20020a056808005800b00268eee6bf2csf33905003oic.11
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Sep 2021 07:35:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631889308; cv=pass;
        d=google.com; s=arc-20160816;
        b=liy+Ubid892JVO6oKW/xptROILazYhwgxyHrSkSu34br6Sg9cwJiprnHv7gbZQqJjs
         kHFgOS9AjPayubaEpAr7qOZtQ5CI6EQ8SseDKd4Fyy/KNHzRu7vTrL0IntsANfTXIQpP
         84bARk90rf57SSu0EbI5xXVhHJv4HG61BTq9tLSmy0xiO/H1IAx88q6HUy5KcTiiNxID
         /+q/SXARdS7jIaC2rmtB619hUARVLed0tutSNDiN5gMO71Ta5WDF762JlH+zX/bt0Ux/
         PQdHtMUzDTfd+UfKITREDgt7L1Fxx6plCL2r6BrbsnlwTJMLrcPlNPl+6xLk+7O5CCdT
         M9BQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Qdm0+nUMk2X0IHJ92DntYfcrNXAnfoCfI8NjW8Y7jr8=;
        b=g4bGrlhgryLEYpv1sLuUkw5Pot9B0PZHeHE26P0H5ggvRrGVfg8E+9NrESPdyh/8Uk
         iVZFC0nKMcXKEOwAcnIa3DHMPcvaITeYvsM6kVxNlkIknm/uQtxge1j6UpzK4ZpMrJK9
         LVLpi5o5xO6upqPn8cibGb1p93QIXbthOMTZ0cyQMJeUs/mu4/YPw+FrktuDuf8Ttq8h
         qajFtzaa45a7SaPjfrH90A7IbqBIIs8licDRbN33TWYts4fHr8UdqWG++Efa5sMySi3P
         9xN0x1mfAihbm3G//yDmJnO3iWjf/9FynU7qtaMv7gNM/uyETcLPZHLDueGhYIZT5q1p
         xK5w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ECs95L59;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::22c as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Qdm0+nUMk2X0IHJ92DntYfcrNXAnfoCfI8NjW8Y7jr8=;
        b=BeB00xpvCrBtKlUhPtHsXeSY1rKye5vVE6frHXSNVm8cv931HmlZx8FgtyKgYxOmEL
         cnkDQON1Dg+BvTVlUo1CsshJ34ZLYlsvVWyLYQQWnCiT3YwzRpGQcKr6TUMsK9xXqLQd
         nDNU+2p0hiMReIF0k0VgbinPkGOu30NygyKaPbiBkmMpeGzeYLeRqGhVqe17EM/+yX3x
         QnINzwyFUuMZeOd7GdMPCR5wRM9jvjVVYHniEF0SVA+f+LluqP1YgVqT65ET7yEeoPOk
         9MlPHy5pu9V88rdXJSExM2QHVVKyzUMaU1zrS63fUFBWjAvW6/K4xxQHmY8yUGUFeHd9
         Es6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Qdm0+nUMk2X0IHJ92DntYfcrNXAnfoCfI8NjW8Y7jr8=;
        b=XmCDKbDJQ2GRr+z+2J2ymi7TI4RcaUBbVWYBq6M/7HDDCpp8M6OMO6stnfgj8l7X9v
         1DAoR2k6/zhwMsPqzW82kwLjsYjMLmVoUdJF7xzJa5+j00Fzx7aw+XIJqkw2AWAysPU/
         xFm2b3LFnAMwrUF8YKTFVMGQ7i8b3H7+P/OuYhbxPeuGimH8715TLIExC5LnWOspLcDO
         hNut9wneO9cRB+sN7qrYTjA2hHnF/DUczYTNOErubh41Y9F4bjgc0oeCVLGiJBv2DJz2
         o5g/mcB4DZMaFARTXXEk+ksumyV6rthwg/gfnq8Ht7taxgRMUdA/9QGt14/kyKTytK7C
         YGiA==
X-Gm-Message-State: AOAM531Jo8XuMRULaisitJ6DEQ3vmqUQ8e5ryNvoM+Swv6ToOGcABv52
	xY5mNFO78x0sYdseQ5AHKPA=
X-Google-Smtp-Source: ABdhPJzyNMohUrEjH+IpGC/kQJ3uuS/oRIwuGr2O6wSJUExwne5DSiCi7311Pbg1uKuBpxLu/kMXTw==
X-Received: by 2002:aca:5889:: with SMTP id m131mr13453248oib.140.1631889308342;
        Fri, 17 Sep 2021 07:35:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:141:: with SMTP id 59ls454725otu.8.gmail; Fri, 17 Sep
 2021 07:35:08 -0700 (PDT)
X-Received: by 2002:a05:6830:1b78:: with SMTP id d24mr9749694ote.197.1631889308001;
        Fri, 17 Sep 2021 07:35:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631889307; cv=none;
        d=google.com; s=arc-20160816;
        b=hU2DDfoM5UzOQ9baZOeEftrpLPSoRO5hWMANolXOVWtjvwcNa7mnmIaaA6A0cEjumq
         FCjI8OozS/iOC/7uqoV2EOOI0cpW75n5k6uIYflEF2PTVu/hx7BSrOYRLAnnr89q+fAC
         3Fq9I1nFb/SuxrMJK3D+3nk6JdU4DiNmVyr+6LRgKlqseScYAlC8OwI7DBsCOb4F6I0l
         DnzDBmdStE64Rq6Swxmzsi5dJm2q9Pob7DEbMNp4BIIJ+4QeU4S5l/WLwM7Ye/I5a/8D
         44NYzAqybOnQFus44XAtK8btKD8IZpppxCrwgPlGg5N7quEYDursiPw/khNcpOjZg4/u
         XpIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ID+EROtCIq5uKg/d863vFLkQbbXUtaQHcxjVUWZxmJg=;
        b=aBF9xDDNgajVlpftZwn61/AF9r8HatOo628w356PIpw1F9vLHgyDGhCUI7KEpPVYwv
         Zx+WiOYI3UfMrz9vnxL6BKdFeM1jyxfw+ci2tcBTyr3GokDDTj7aNkwovn9/VbxYpikY
         HAURzkQl2lcaEmfB/qOEeZ2bMkgvVd5JizFtJcHZbyCBdBHitILygdhBH7dYpAlzoxcZ
         SPCQF3DShVp4VJ8QEm4IRKG9LtNb5MPaO0pXkxRMc0TVjmYpWlVkE8PaXbm7Ifntaku6
         uOvLRlWpB3D6c1LB8oJ3alwPJPfi5488bTMEZjwXhj1Pzkor4GqM977casfFAg7AO644
         MsiQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ECs95L59;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::22c as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22c.google.com (mail-oi1-x22c.google.com. [2607:f8b0:4864:20::22c])
        by gmr-mx.google.com with ESMTPS id bf14si670196oib.0.2021.09.17.07.35.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Sep 2021 07:35:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::22c as permitted sender) client-ip=2607:f8b0:4864:20::22c;
Received: by mail-oi1-x22c.google.com with SMTP id n78so929384oig.6
        for <kasan-dev@googlegroups.com>; Fri, 17 Sep 2021 07:35:07 -0700 (PDT)
X-Received: by 2002:aca:f189:: with SMTP id p131mr13881383oih.128.1631889307519;
 Fri, 17 Sep 2021 07:35:07 -0700 (PDT)
MIME-Version: 1.0
References: <20210830172627.267989-1-bigeasy@linutronix.de> <20210830172627.267989-2-bigeasy@linutronix.de>
In-Reply-To: <20210830172627.267989-2-bigeasy@linutronix.de>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 17 Sep 2021 16:34:56 +0200
Message-ID: <CACT4Y+aj3UkhEBq+ROyM=Ns138xpEfCNXSvGRLAXTFyOVkFA8A@mail.gmail.com>
Subject: Re: [PATCH 1/5] Documentation/kcov: Include types.h in the example.
To: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@gmail.com>, Thomas Gleixner <tglx@linutronix.de>, 
	Steven Rostedt <rostedt@goodmis.org>, Marco Elver <elver@google.com>, 
	Clark Williams <williams@redhat.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ECs95L59;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::22c
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

On Mon, 30 Aug 2021 at 19:26, Sebastian Andrzej Siewior
<bigeasy@linutronix.de> wrote:
>
> The first example code has includes at the top, the following two
> example share that part. The last example (remote coverage collection)
> requires the linux/types.h header file due its __aligned_u64 usage.
>
> Add the linux/types.h to the top most example and a comment that the
> header files from above are required as it is done in the second
> example.
>
> Signed-off-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>

Acked-by: Dmitry Vyukov <dvyukov@google.com>


> ---
>  Documentation/dev-tools/kcov.rst | 3 +++
>  1 file changed, 3 insertions(+)
>
> diff --git a/Documentation/dev-tools/kcov.rst b/Documentation/dev-tools/kcov.rst
> index d2c4c27e1702d..347f3b6de8d40 100644
> --- a/Documentation/dev-tools/kcov.rst
> +++ b/Documentation/dev-tools/kcov.rst
> @@ -50,6 +50,7 @@ The following program demonstrates coverage collection from within a test
>      #include <sys/mman.h>
>      #include <unistd.h>
>      #include <fcntl.h>
> +    #include <linux/types.h>
>
>      #define KCOV_INIT_TRACE                    _IOR('c', 1, unsigned long)
>      #define KCOV_ENABLE                        _IO('c', 100)
> @@ -251,6 +252,8 @@ selectively from different subsystems.
>
>  .. code-block:: c
>
> +    /* Same includes and defines as above. */
> +
>      struct kcov_remote_arg {
>         __u32           trace_mode;
>         __u32           area_size;
> --
> 2.33.0
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Baj3UkhEBq%2BROyM%3DNs138xpEfCNXSvGRLAXTFyOVkFA8A%40mail.gmail.com.
