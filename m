Return-Path: <kasan-dev+bncBCMIZB7QWENRBUNEUGZQMGQE3JHK2BY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 40BB5903D78
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Jun 2024 15:34:10 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-4218447b900sf14498385e9.0
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Jun 2024 06:34:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718112850; cv=pass;
        d=google.com; s=arc-20160816;
        b=r2i341Sl2o9ktK6Rx4KhctyN+r8KotnXW2unSRstZPfyGm8T6Et7e4SRkNy2yWS9y/
         zrrr1CSxoRVtpTB/AASzlPqaxF7yNVmS25OJAmAuOS41GIS2dLgrf5ikg+MGChRHt1jL
         cDdmQB+/0RqTLtKwy6OIP4DX3lDZvvH/W1pZS/LNaLWK4ZhErAIyHRvWK2OnG8IqXdPw
         MislWsDHBobXkS+qYQBJBACnSHEEp1T02w7EeDgXNAy/TVfn/zW9YwbgHPorX/2rzK3M
         3//W92E7G+GuoRGPWMT+5tWPIWnXgX99kpJ+t60Dh2/WObt1RyjVUAGfu7peGn0200Oj
         An7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=w1TQVjGd8rOAY3ZPlwcXTzU205bBppkn9TGMx6StJ40=;
        fh=IUucX/6A4uRMM8brc+g9US9xU4DxEq7Ss3BB7Brrlg4=;
        b=jrEJZac/wZGg/FS52gSOAMw5OYY4HCuwlntOFLZzb19+svoEEw2Xe4u7wsQZRHQIOz
         QCwjjrQXbhzGu8oiRbPBVAwcNrWLi9b+IVycVV8luSVf5NwGp2prFVsZtbbNYvo4M6fo
         fTUz+nrPY1jNeAkr9OG5QtbaLZAYQl7tjG22UgR6ZPXIUxYMeAZD+6eJ4jvv29+ySzXh
         I2XGhbDqa+QNGfzTFFqU4T1kFOu3IV1QKbNm7GTSAmy64xpUYXiL8YRdGUUzzXCCIC9O
         bpwcFoMirr7jaSINWo1QlqVjOwndC/r2BwDwFyfF6J+vqbYyHUkc0WN9vBxbUi/lq/Bh
         E5bg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=WoaTL9gj;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::535 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718112850; x=1718717650; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=w1TQVjGd8rOAY3ZPlwcXTzU205bBppkn9TGMx6StJ40=;
        b=gYAHKTOmW4rtj6rOUWa7LkS0fcMPtZKO4ypI7niUSPLoNf3DVKhLMbguGOLPc68s6u
         4Y/4xzOJO/PLs3NhlBUew6XaJBHGpozLIwflhC291PUsMcugCYvtMEvyWTAR66RkDZUT
         HRSWlF4SgXI3ui4A+iuBeCVcOkKJS6W/d9XZJ38lmfbtD16nwzBGOOGNH5LRxFySUz48
         xgoWJlw0I7MlvowxQyDHCLdRCbAwlvImxG8vJ5f8HpkXFsp7x6j4QuNZ3/7QyrYcH0ST
         nBRl8E6V8b82CKTJS9eK0mVh78r1AF9nydPVAD47BwsBQV67ygqvgKXJNalrGx1cuCg3
         4z+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718112850; x=1718717650;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=w1TQVjGd8rOAY3ZPlwcXTzU205bBppkn9TGMx6StJ40=;
        b=fS5tDIJjwJYnuZ2hI+OoOAF4NqvvjNod4KGMFNQxgXAp0+EzPoIjOe0Rmmt+JkUKmv
         KL9fP3YePhOxzXBKWwjtXU7d8skNqFP/11qRnl5PI0SPL2SHYhMpIn6WuupWtTuF73yQ
         sB+4OUgYtMsewv42042iHsUmxZdpJgTR3Veqdl+k1iqp3tabTD2xJ4QoDXpn5tUQcTdz
         XaGElYISTRFsoiFNnqWiA8QYEyuHLiGfQZzxwORJ4kNrqvSgZBFJSJUN95oZh4lL4nSI
         sPMebxRRJVubKeTEyl1HYEdHnlSjgsSGL8+MoArAEyr8zC8Tw4r7nI2kPlm2mzX6YhaU
         JgcQ==
X-Forwarded-Encrypted: i=2; AJvYcCXuTW146qLwEe3YDreB6YU9StgUE3dPG74iCiKYklIEbbKVovf38NeDsYUZT3mB8V/MFi2mzMZQwRn2GFdeNoaLa4tK+6sgyQ==
X-Gm-Message-State: AOJu0Yy2+ghuAEjlzdcyT7F8Wgmt3scYHNq9NsmvrqDyi7lM/XAiEObK
	X2EU0IwlEOLgWTHmVJ+ABne7eYv9FCWSsvl5TBSC2qfrFUrhWHIx
X-Google-Smtp-Source: AGHT+IFtFvkibDYBwJT8LKECEsRpfa5o1GGm5QTR2J3Ybj+vpy28LcG6k589qZzpja7tYJanDKc8Tg==
X-Received: by 2002:a05:600c:1c29:b0:418:c6a:1765 with SMTP id 5b1f17b1804b1-4223c8d5938mr25819675e9.16.1718112849225;
        Tue, 11 Jun 2024 06:34:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:598e:0:b0:35f:d3f:68c with SMTP id ffacd0b85a97d-35f0d3f086els2058361f8f.1.-pod-prod-00-eu;
 Tue, 11 Jun 2024 06:34:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXK/4Umez2u5g430v23eJ3V20cEHHyx2l0Mvgm1xJVUMbQItlND4Lr6GxaRHZdUi3u1j0mbyBb/EQTrXUOwDLGJROKu3YAPcRh2Uw==
X-Received: by 2002:adf:ec51:0:b0:35f:2374:5515 with SMTP id ffacd0b85a97d-35f2b28a785mr2544634f8f.15.1718112847333;
        Tue, 11 Jun 2024 06:34:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718112847; cv=none;
        d=google.com; s=arc-20160816;
        b=FJonuVFSmIRkqtNCnalEDZmgeyavXXQ8y0JHJ21AGC2hOL4VwT4izrs4y/FpIwEd96
         tkuqrZVHlSn1EtKWU3+WT9/oTE5eLymBfH8h/kCPZokm/ET8Z3vAnnE5zAWBcBHkCNtu
         NyMheF3eLaM5CHN9VNnKIS190LMu6y4A3KCndnShXPOMVyiMrYi6SmhY/8jHRl1vtYrZ
         5dTbljk0/vqWK74CohFAXU29uw1cS+KxILe0YeNEvVG0RKNih12SrpTRRr86P1f1XHim
         gikcWEowJeiov4B4YB3RU0OCKVEuZZYPC5dvvo+Lx3JeIZdepY/wyao7QgIORqXRgsEV
         aGaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=RonLSH5VW0CRVsgXmgBTcMVlLlRjvCFzxuDnDau0nJE=;
        fh=3otlcSyVKHDdC0v9wYYOQus3hRbu8stbEHlHkCpNdkQ=;
        b=usUM/LfF+SK25v8BXUnRnBQiH5RZeLGi71pwXd5u4/+Np2oTuluqB9eYyGM8+ebu9y
         qiOb6hTnpB2fra9kOMUtWi3IFRqmUtrpuYJZDBMLt2smVfc2CXd+Av7FQkZsX6+lig6+
         LPdqlc6rQXnVVuaiF4hK81XksCktshltP7mi2SdoBdsOqQBQ7dSwKxJcgjl4NAlie9me
         P44bmrG2W/RNX1KS6We0NOcsuw3mqcIQcR4cf+m4nzWKQaZ7B/ZAYYwcu1TUU1Uu0iLi
         Hhq3jvKyZ3dkV/V1u0BcHcpxsjNLvbnyEZYOZTXEHMJXp+6aQMyiy5olyKh3K+ywidki
         yScw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=WoaTL9gj;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::535 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x535.google.com (mail-ed1-x535.google.com. [2a00:1450:4864:20::535])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4225b979165si832535e9.1.2024.06.11.06.34.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Jun 2024 06:34:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::535 as permitted sender) client-ip=2a00:1450:4864:20::535;
Received: by mail-ed1-x535.google.com with SMTP id 4fb4d7f45d1cf-57c8bd6b655so17006a12.0
        for <kasan-dev@googlegroups.com>; Tue, 11 Jun 2024 06:34:07 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW1bGpkbcgtyBvOj+5m3b+lxPriJnND4Kxn3KvGccjKAXkshnvW2+8fIb/h0PP4XNuDUSSNGirY0MlJDl1Pu4nGeIe4+lMUMeAteA==
X-Received: by 2002:a05:6402:354c:b0:57c:9853:589f with SMTP id
 4fb4d7f45d1cf-57c98536334mr103562a12.2.1718112846492; Tue, 11 Jun 2024
 06:34:06 -0700 (PDT)
MIME-Version: 1.0
References: <20240611133229.527822-1-nogikh@google.com>
In-Reply-To: <20240611133229.527822-1-nogikh@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 11 Jun 2024 15:33:55 +0200
Message-ID: <CACT4Y+YpMz8f_Z9G3QeFzcX97FXY6QTSf8r_u4TQwk6xiO8+eA@mail.gmail.com>
Subject: Re: [PATCH] kcov: don't lose track of remote references during softirqs
To: Aleksandr Nogikh <nogikh@google.com>
Cc: andreyknvl@gmail.com, arnd@arndb.de, akpm@linux-foundation.org, 
	elver@google.com, glider@google.com, syzkaller@googlegroups.com, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=WoaTL9gj;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::535
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

On Tue, 11 Jun 2024 at 15:32, Aleksandr Nogikh <nogikh@google.com> wrote:
>
> In kcov_remote_start()/kcov_remote_stop(), we swap the previous KCOV
> metadata of the current task into a per-CPU variable. However, the
> kcov_mode_enabled(mode) check is not sufficient in the case of remote
> KCOV coverage: current->kcov_mode always remains KCOV_MODE_DISABLED
> for remote KCOV objects.
>
> If the original task that has invoked the KCOV_REMOTE_ENABLE ioctl
> happens to get interrupted and kcov_remote_start() is called, it
> ultimately leads to kcov_remote_stop() NOT restoring the original
> KCOV reference. So when the task exits, all registered remote KCOV
> handles remain active forever.
>
> Fix it by introducing a special kcov_mode that is assigned to the
> task that owns a KCOV remote object. It makes kcov_mode_enabled()
> return true and yet does not trigger coverage collection in
> __sanitizer_cov_trace_pc() and write_comp_data().
>
> Signed-off-by: Aleksandr Nogikh <nogikh@google.com>
> Fixes: 5ff3b30ab57d ("kcov: collect coverage from interrupts")

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> ---
>  include/linux/kcov.h | 2 ++
>  kernel/kcov.c        | 1 +
>  2 files changed, 3 insertions(+)
>
> diff --git a/include/linux/kcov.h b/include/linux/kcov.h
> index b851ba415e03..3b479a3d235a 100644
> --- a/include/linux/kcov.h
> +++ b/include/linux/kcov.h
> @@ -21,6 +21,8 @@ enum kcov_mode {
>         KCOV_MODE_TRACE_PC = 2,
>         /* Collecting comparison operands mode. */
>         KCOV_MODE_TRACE_CMP = 3,
> +       /* The process owns a KCOV remote reference. */
> +       KCOV_MODE_REMOTE = 4,
>  };
>
>  #define KCOV_IN_CTXSW  (1 << 30)
> diff --git a/kernel/kcov.c b/kernel/kcov.c
> index c3124f6d5536..5371d3f7b5c3 100644
> --- a/kernel/kcov.c
> +++ b/kernel/kcov.c
> @@ -632,6 +632,7 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
>                         return -EINVAL;
>                 kcov->mode = mode;
>                 t->kcov = kcov;
> +               WRITE_ONCE(t->kcov_mode, KCOV_MODE_REMOTE);
>                 kcov->t = t;
>                 kcov->remote = true;
>                 kcov->remote_size = remote_arg->area_size;
> --
> 2.45.2.505.gda0bf45e8d-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYpMz8f_Z9G3QeFzcX97FXY6QTSf8r_u4TQwk6xiO8%2BeA%40mail.gmail.com.
