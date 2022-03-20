Return-Path: <kasan-dev+bncBDW2JDUY5AORBHFQ32IQMGQEKOAAOXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 945E04E1DDC
	for <lists+kasan-dev@lfdr.de>; Sun, 20 Mar 2022 22:09:50 +0100 (CET)
Received: by mail-pg1-x53c.google.com with SMTP id b18-20020a63d812000000b0037e1aa59c0bsf6437247pgh.12
        for <lists+kasan-dev@lfdr.de>; Sun, 20 Mar 2022 14:09:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1647810589; cv=pass;
        d=google.com; s=arc-20160816;
        b=aojJlwhhGfnmzf5fBdC5T9uJVOvZKzZ0wH5sjmpP5X2TZHxmB3LiBirOV4VChnGlG0
         HNaQIa+CetVUyjzSCZ1wSs/Fs6gS0Ch9Xiujgxa3KV4gDW2N3I0XnryGZNRnOfV5A/sA
         gEoJ+vGKz7efvWpEArxs7CXR6gL/7EUnR+s36ruqyYyymKoRVC777vXI4h9TQJ3XZZ7C
         9iJOKQsAcI7/qn2yWcmYQygX1XX0z2IuCHK4LFt0jDLWD4LRtEMwD8PcyvVt4Mvu6iOL
         V/G1zjK1turWyZir5iQd544hwYmaKimMgcYGH4YOgfWH0ZgyBN7GYzN4CRAyfHMq4bkM
         YWVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=cfs+4bYaelQc1jmRA8VOL9RxEiTLBAGKu/v7Xswsr4Q=;
        b=MC27Vg1LR8bQvCtQcncHh85AOxETetvW0I426My3vdWItTjqll/pHjT2imARCJDpA+
         3lsauDNZ2ujLrRLIzr5cj6K5uemdY6u39siOLHw6WUoLzN3YRsghrlbUR2s8AFsublIp
         pQxqu49rzFfQH/rfq/0LIGwLHyPo4Tn2+QIjpkFF3UqTWx5N8f7fj6xd4/1l8nk3WFHj
         gVBF3mn/AIsYs0fCisDeNm6Oat7jW8/dnCcSdMsVk0R/0RYf1lnJ+4Ql3Pp5x0pzx0o0
         hQwjuAzwNsNBxxiQNjhb9cwgGduBZzKenTxm/cU4l1u7cbCgRKSpLxaULKYTl59Lorjk
         y2mA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=pUR9BPsX;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cfs+4bYaelQc1jmRA8VOL9RxEiTLBAGKu/v7Xswsr4Q=;
        b=sLFzYpUatc07md/xX02feTvwwOwc3wqwKo8RgF2WIlCTjHuMX8xqlrDn1RxPDxRbbn
         d2VdC0D/dP964pfJgHxLu4R9jaS5fPEnjEOq+w5ho4GOTTfOCTZW1af9TTfzH9jlSySi
         8EpiFfakOkO7lxAAJRW82xbphlUv1xHkayf2V7W/vCLoer1AZtI//CiWoXS83bmhDH+E
         kWJZi/gXEKnek2OClCe9WsKLs0wS/1XOtwvFDBby/kh5mOx220Mwf55KGyLBsp0by8Y8
         UwIPcBnyh2e+1783KBZ+/C1ZuwJax855rvFiMqzr1AZhM61ID5bR1TT4XHdk/v+8h0+7
         252g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cfs+4bYaelQc1jmRA8VOL9RxEiTLBAGKu/v7Xswsr4Q=;
        b=Wzb3O8CtDP0ucVhg6u7FquAhTPhzTp1zuwlwDK/+DsA9tLMiMcfSKQIxKv+Zs7H6mA
         aWG0Koa8AXfh5FRSKrZ8PP2nX5pBLScvVeaj8zJ4+VUp4QGW1qvpA3hV+/fMIP7T/C5A
         zlkK0c/KFuCz3jBEZqbNp/Vfw4IWH+XVNjyYsCzr57c25tKinM6MW55E9IpU3XT0FgRH
         D7blKyxJRBmoXvxm0UEMc4pXfRbBzMcSgFHYn3k4RZ3X3NLh+pK+MGu4u4Q4r6T6lCcf
         FGd3VEFnV7R9v10Kv9T1hHswhl0hvaYvbO7zUJjtbjHV0buGZozO2VTWMyH6OTnUF1b/
         ybJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cfs+4bYaelQc1jmRA8VOL9RxEiTLBAGKu/v7Xswsr4Q=;
        b=xKCNedF+6jTk6ZsW3WEnyNTMBk9dS+kI+9HNgoNxaMtxvVgz8Bs4La0gQIfpJguZi6
         +qJtNayqKtE3XeoO2ADCahuPLfzg0QXmseg1hIvKBzBIghshYPqxmoJRx5Jn5OsFLyvy
         ZIE9iAWYopmgpHff9TUjDegm5VG1mlXQJGrsek+FC6scVOVMrrowMn95CcZTRb3kyWF1
         zkgqzAm3aGMafSGC9ozS4Se2w2GJv7HPgpegXmOdVgj9Lz2OFmRoX0iDShEnsbA2x3Le
         /eKoV0hjPp5nchiN3Cy4qxYE57/QRSgYBuiTvT91KOLr7TBpTRFBjtG5s6kCWElb+rhh
         MUYg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5312FqRjsFHEbkvzm0cCT5+DoAc8obIEjPvE/sutj3J/2U527Jzy
	rxfKkbpXK8gG+DNgvwAGG8U=
X-Google-Smtp-Source: ABdhPJzqMLQ+qZ05SLxLu3bc3Qq5BX78Lh2peF7OHwOc8DfTkNuDAuEUcqF1iIv2izLci9hQyVhMCw==
X-Received: by 2002:a17:90b:4c44:b0:1c7:1326:ec90 with SMTP id np4-20020a17090b4c4400b001c71326ec90mr2637736pjb.87.1647810588936;
        Sun, 20 Mar 2022 14:09:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e887:b0:154:475c:c005 with SMTP id
 w7-20020a170902e88700b00154475cc005ls1683887plg.2.gmail; Sun, 20 Mar 2022
 14:09:48 -0700 (PDT)
X-Received: by 2002:a17:902:e74d:b0:154:46d4:fcd1 with SMTP id p13-20020a170902e74d00b0015446d4fcd1mr4872770plf.58.1647810588352;
        Sun, 20 Mar 2022 14:09:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1647810588; cv=none;
        d=google.com; s=arc-20160816;
        b=YrsKh+sHOvb4jaM4hHW4vZhc/K7SOONK7ljmRWH7ptFMcMEm8Te0fp1kzf9FVFILTt
         cKJP7pNsOI0lolbjCdvWKZOTOWThk3BSbqz+rHZ9sJ9aAJXAaizKYg+Z/PLcPmSYByxz
         DBqjcHByL4V9NdqqSnvx0OWaYa2C4CtbXYJfecynmozaHiKbFMryYrjZaaxs/6eG+ySe
         IkFnup6gR0q7ltNEXWWYsKNRG/8ObUbgphk/4+2iVTXFa5Iux/gWoqag6SbsiKkepFlo
         ZV4ywDNHHlsJd8gK3Otdy+SiOROyya3BrvQyqfNJiCL6HOgaIl9ucecUwb/AG4pRYvCx
         xbIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=3yhe1yZzGEpebfSEI4NmtuOUmADVwotj/x5O7U8D/9Y=;
        b=eGVeW7BnLDg1mRRK36sk2Q8lIZkVlRAH1q5D9Mg1reQMSl2KTvGyIdAP5miajbQujb
         G7REaoGc/m0OtGJ6bkIfRDKy0Zq6IakTXyk0FiPaG/EYwAvhVVY1atKs912ertCUCV6k
         9BoZPd9OkGuuCeUTl8+z3vY0Z+BvDPyzQn0uaPQeNwT3XblllvfO8uxrRs6Xfr3jGd46
         +pxzKXDFAqvu6xHiz/B707a8UywQr2PvIrCVLtHhdK75JuDKqnnD9cAbZY0yMp7YjY+B
         2emFfMJ/IfsiHvcIgecurYm7wKeUXFMHmcJXjB25mnKb3yh5OQTXNJXLleM6f9gmXFUZ
         kEkA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=pUR9BPsX;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x12d.google.com (mail-il1-x12d.google.com. [2607:f8b0:4864:20::12d])
        by gmr-mx.google.com with ESMTPS id t20-20020a63d254000000b00382250b1e15si393443pgi.1.2022.03.20.14.09.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 20 Mar 2022 14:09:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12d as permitted sender) client-ip=2607:f8b0:4864:20::12d;
Received: by mail-il1-x12d.google.com with SMTP id 8so149360ilq.4
        for <kasan-dev@googlegroups.com>; Sun, 20 Mar 2022 14:09:48 -0700 (PDT)
X-Received: by 2002:a05:6e02:1a4c:b0:2c7:c6fc:79f4 with SMTP id
 u12-20020a056e021a4c00b002c7c6fc79f4mr8215769ilv.235.1647810587864; Sun, 20
 Mar 2022 14:09:47 -0700 (PDT)
MIME-Version: 1.0
References: <57133fafc4d74377a4a08d98e276d58fe4a127dc.1647115974.git.andreyknvl@google.com>
 <CACT4Y+ZtahUje36PKfGYLVkb2SawMXOC9aPNwgfNgZ1ujCAVBA@mail.gmail.com>
In-Reply-To: <CACT4Y+ZtahUje36PKfGYLVkb2SawMXOC9aPNwgfNgZ1ujCAVBA@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sun, 20 Mar 2022 22:09:37 +0100
Message-ID: <CA+fCnZekEu705yAX85wsCQeN21rk0tgS8ib6V8jrH_AscubbBA@mail.gmail.com>
Subject: Re: [PATCH] kasan, scs: collect stack traces from shadow stack
To: Dmitry Vyukov <dvyukov@google.com>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Sami Tolvanen <samitolvanen@google.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Linux Memory Management List <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=pUR9BPsX;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12d
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

On Mon, Mar 14, 2022 at 8:17 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> > +static unsigned int save_shadow_stack(unsigned long *entries,
> > +                                     unsigned int nr_entries)
> > +{
> > +       unsigned long *scs_sp = task_scs_sp(current);
> > +       unsigned long *scs_base = task_scs(current);
>
> Just to double-check: interrupt frames are also appended to the the
> current task buffer, right?

Looked into this and found a few issues, will fix in v2. Interrupt
frames will be collected then.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZekEu705yAX85wsCQeN21rk0tgS8ib6V8jrH_AscubbBA%40mail.gmail.com.
