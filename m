Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIXFRGIAMGQEIU7V6GY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 062A94ADA22
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Feb 2022 14:39:48 +0100 (CET)
Received: by mail-oo1-xc38.google.com with SMTP id v10-20020a4ade8a000000b003177422e81dsf5031793oou.3
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Feb 2022 05:39:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644327586; cv=pass;
        d=google.com; s=arc-20160816;
        b=ALYlTNqzlK31HvEfu6dNuH0eF9jUsNFnoBGBlUEAiQzT5o8tmm5JNKfdGGxgsjQpMH
         mE0r1CzC6w75/jJt6j/fwoFE6Dw09xScNgP147kesJuqdDZETXvI/jCzbchQIHiRzZ/8
         qyCK/oSBllAaHSivTTyaGp6Sy2eYlASasFpDjSHkc2SYSoyqMXyKj9axTkS7Bohtkw+R
         8oHT/QVEfQbcAlR302pk4I4g2/sGLS0rnZF6FS4KYBB3LsIrseL3B8fVHKSn3vsAAFqA
         CS0fhZJ0CWjkBtu7eZYbM9F7fy4EjM6b3WxLl5wliGMRIv7TT2yI1s6y+jNda7qfHbil
         orIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=PeNnL7HnSqc8fm9CK2u1S8g7CqR7e2CQsEzUpnr4uI4=;
        b=Wqns1OnKInW6f7n0m8ZBYSWBbldlJEiHS4W8R0B6MQ17ZI9QtzLlyjX5NvL8KcxNa+
         ozYOEMbQgrgyIGtTjzPRbckfEyR79Uz2iAo/GGmE4T8axwDN/kISd6ys8g5DpQmC4nCe
         fs5F+sIofzBrdSYCTRaf/eyHJLugMc1pVYVuGAF2LxN0ZH4Tob5QNNiegTmPttCyq0N2
         e7Ejl7jCmNQoa6jENaWSdhHoiMDf5eq9ef6QnijEhMMEIqY6Hnt1o4mFdESyXnVeSpXw
         ZX+Md1RsQ8KCGbvr07x7MtT0/F6dDnWdWRJ/dcLW5HJMkFYyr0het2nltWSEUwYFa/Ue
         SA9g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=JBVhCpQm;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PeNnL7HnSqc8fm9CK2u1S8g7CqR7e2CQsEzUpnr4uI4=;
        b=mCdOHNjDkkHKa5lG99lZrLGAT3N0A+WZpBVY54HrNx8smpHfeNTG5wgOejsOmtgf+W
         mCUiLNrpFV75sfpuC8+dVdyqt/tbpVfzpnUeRIWscndc685ye5lzj+NSWq6zxHF6wM27
         wPAGbN9LKiGSb1i+TQu2BJQhGovh8k2/zQIU/1AQlTrB4G5LdEo2cDuYraWU/gA2tZWK
         VIqeeFjeOoHNBfukUboNlQvR/0vDNePZdCd2Of91XfYsRAFdDKEJtcnwpQTzBf/fI4o1
         LKonhBbVOc9knNXm7WwsbbFVdb5OLJ3THjPdJupJq0SjEC5tm+TDmrz8dBLKv72Meic3
         WMnQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PeNnL7HnSqc8fm9CK2u1S8g7CqR7e2CQsEzUpnr4uI4=;
        b=tvdvMr0sUaSpDQGLWLbxH6j6NXZIclmcb4bY5+q4QS+Ec2+iv0whUGxLy9fdbnV+K+
         VwSghzzkcNYYd3Xhms9DYJnb6i3PYOMF/SJ9ej6W39tTbWdTN1qpF2Ems1ZGHWukaQoi
         osnv7t8OtTvaJZXvP4nSvU+zAPKAavCbDO4cIvPWt6tOu6se8CzCU9c/0lRS/H+4FjYZ
         qePvfkA8TmjRXXS+woCoUHHFdfxyW6QsK6llQ7iukAJ0qPjlKb5aonTnfKkuJka5Fod6
         Mw4HWpv9cGVWEJkeNENRahz7nXHY11V1uqui9ZWuKWP7jGIQV7MdH7o9XazFC6FDNd1t
         WWJg==
X-Gm-Message-State: AOAM533eVTn6nSvneFkbqYtafrpC/fD0dx/7DPi92kOEj+3sMX7eb4qa
	qh/0DDboMWz6zXjAewHW3EY=
X-Google-Smtp-Source: ABdhPJyOSKz8uz/Q/jUVBpVZj+Wx40PpLWK0LErSMoLYAvulfUhq0jRaqWiqnyorwY1TO7gsZxP4dA==
X-Received: by 2002:a05:6870:d502:: with SMTP id b2mr374265oan.280.1644327586615;
        Tue, 08 Feb 2022 05:39:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:2b0c:: with SMTP id l12ls1740158otv.1.gmail; Tue,
 08 Feb 2022 05:39:46 -0800 (PST)
X-Received: by 2002:a05:6830:1d1:: with SMTP id r17mr1829621ota.240.1644327586018;
        Tue, 08 Feb 2022 05:39:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644327586; cv=none;
        d=google.com; s=arc-20160816;
        b=WWuSNL8Ddq6VBcu+4c5Qtw3WH9E65M6UoKYTCbUWJqIfa1hIo3HabuiZFvK/JXwq2P
         pGi5JJ/48jWk2SnpXfs5F3j3lkK40On7NFgdyZYtUkcUSfawmYRhdLlfprjdofh2pjX+
         D/Xag+EG8EA9d8OGh4QQ1/tAb3FAHtKnQTxRyoLCboqSXSJxrq2Y9wXXdPNTYlIqmcBd
         Xc1d/HIIvDhx49YfnpMUDeSGr+k7v68/D4PW3qBXR6UcMoZ8pqZkdfHls9jEiX0RrW07
         9LLJAVJrC8VkQo8tKboCKdbqTLeBBgOZJK9LyEjGy3Q7bxcu6yVobeRuPsuDcDTraAhY
         hpOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=AB43GeMhzoWNJcuHGVxX4xPDF6JvmahIqFg1wRbGD9E=;
        b=Dnai0PsKDKcRRb1g54l3PFuYotjHOY63+t3IbjZIG/PEcOhpqpLIN1eza5G0nC9dpW
         a5316+QpXZl0/oOyMrvnZoRBN8E8Zrlv07sFNS/r9ZHy1UBolRR1t0x5lSNubDIF2Dnu
         zsYQpIQALsljy8Ncf/5xVVCxJpos6nI9pkRqcNI6e8pvjgjn3kFTowG/TrFe1ptGSTXd
         1CmfHGm3x0auwHvQ8t2JyLEmMcUU6H1O7ejS8LvNPubG7f2Df9EQ2alPsF7QwIAASshK
         djzD0Cn/jwsnTKtcumZTGdeBVokia9IBzYH09220AVpa0Ncra4OknWz71a6lxXlhQW8E
         uSVg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=JBVhCpQm;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb32.google.com (mail-yb1-xb32.google.com. [2607:f8b0:4864:20::b32])
        by gmr-mx.google.com with ESMTPS id u43si1514279oiw.2.2022.02.08.05.39.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Feb 2022 05:39:46 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) client-ip=2607:f8b0:4864:20::b32;
Received: by mail-yb1-xb32.google.com with SMTP id v47so24940188ybi.4
        for <kasan-dev@googlegroups.com>; Tue, 08 Feb 2022 05:39:45 -0800 (PST)
X-Received: by 2002:a05:6902:1548:: with SMTP id r8mr5071533ybu.374.1644327585600;
 Tue, 08 Feb 2022 05:39:45 -0800 (PST)
MIME-Version: 1.0
References: <1644324666-15947-1-git-send-email-yangtiezhu@loongson.cn> <1644324666-15947-6-git-send-email-yangtiezhu@loongson.cn>
In-Reply-To: <1644324666-15947-6-git-send-email-yangtiezhu@loongson.cn>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 8 Feb 2022 14:39:34 +0100
Message-ID: <CANpmjNPxLgosrY=CH9GpwHmOKFbCuPQfLBFS+QBZGKiQC-od9w@mail.gmail.com>
Subject: Re: [PATCH v2 5/5] kasan: no need to unset panic_on_warn in end_report()
To: Tiezhu Yang <yangtiezhu@loongson.cn>
Cc: Baoquan He <bhe@redhat.com>, Jonathan Corbet <corbet@lwn.net>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Xuefeng Li <lixuefeng@loongson.cn>, kexec@lists.infradead.org, 
	linux-doc@vger.kernel.org, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=JBVhCpQm;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Tue, 8 Feb 2022 at 13:51, Tiezhu Yang <yangtiezhu@loongson.cn> wrote:
>
> panic_on_warn is unset inside panic(), so no need to unset it
> before calling panic() in end_report().
>
> Signed-off-by: Tiezhu Yang <yangtiezhu@loongson.cn>

Reviewed-by: Marco Elver <elver@google.com>


> ---
>  mm/kasan/report.c | 10 +---------
>  1 file changed, 1 insertion(+), 9 deletions(-)
>
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 3ad9624..f141465 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -117,16 +117,8 @@ static void end_report(unsigned long *flags, unsigned long addr)
>         pr_err("==================================================================\n");
>         add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
>         spin_unlock_irqrestore(&report_lock, *flags);
> -       if (panic_on_warn && !test_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags)) {
> -               /*
> -                * This thread may hit another WARN() in the panic path.
> -                * Resetting this prevents additional WARN() from panicking the
> -                * system on this thread.  Other threads are blocked by the
> -                * panic_mutex in panic().
> -                */
> -               panic_on_warn = 0;
> +       if (panic_on_warn && !test_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags))
>                 panic("panic_on_warn set ...\n");
> -       }
>         if (kasan_arg_fault == KASAN_ARG_FAULT_PANIC)
>                 panic("kasan.fault=panic set ...\n");
>         kasan_enable_current();
> --
> 2.1.0
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1644324666-15947-6-git-send-email-yangtiezhu%40loongson.cn.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPxLgosrY%3DCH9GpwHmOKFbCuPQfLBFS%2BQBZGKiQC-od9w%40mail.gmail.com.
