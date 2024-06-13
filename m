Return-Path: <kasan-dev+bncBDW2JDUY5AORBCPVVWZQMGQELKQG4TY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id B7E3D907F2A
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Jun 2024 01:02:35 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id 38308e7fff4ca-2ebe4b327a6sf11785711fa.3
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 16:02:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718319755; cv=pass;
        d=google.com; s=arc-20160816;
        b=W2wqa/CIRrj0JEC8ko6SGypEQsCh9mFfYxjXhP7vBcl46hoezl8umPLRYmoS/nv6JT
         Oudu73wlGibPlbc0TLWWuxdbe4Fqe2GghRxkPg41EDT5k5tBTb2L0VcyUGz23ISfmVXO
         UNOWY4XBC/0e8ITU60ze4qgbqDXzwR1mt4wmBF7xRMvVKp0xAGVt244ot8JwM4XThSWR
         nPfWeKN24Tk8FmAlOPYuRp3oZuLFtvXO42F9Us1uATz4DbojGbKpnudjJ7SgN9feofYL
         VWfxE2CPyLsy+AsolF11+2sGB6JwkFl6ubwCb/bGqFQyrHLLFI5r5NagrB0sruH9Fo7h
         YDVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=/AQv1n1/x8DjyJ4L4oNqavGPm1HZT7T617b0URW8QIc=;
        fh=BxnzPZ2j8y9YfLYgNlhBAwxJuzrrBmUg29ampIW+YHo=;
        b=0mmhfwrbUUKoxK8ghedxdKZZRk2AZLg526GEdKwFpWpd2JnPisiGLfTwU1FXJoHoFW
         LiR4XisIgSFEWEpO+OrdsMx9UNjMDIZ/dxjuGBNsUmf6pMoZJ1+9YHsjCYxNAifaeqD6
         moV61C9FVtDUa1qjsTdqEK7vrRWfNcHrSjZ81sYKwEskhyWBv+s8iJMtv7hTs2bcjQjE
         mdhUj69NY5rCigqa5uLatA+6eiSE/2GG8NzfGSBYzE1zfvPmShZR16/QUJI+bh1KMjcX
         AEtvx8Awos4+TQw4SdoBcsLK1PnQ1wpjsuuqR3HxQQ1VInUEJKVF3deAeL/qBex03how
         0EUw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ahAUtxwm;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::434 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718319755; x=1718924555; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=/AQv1n1/x8DjyJ4L4oNqavGPm1HZT7T617b0URW8QIc=;
        b=QosJZ7rXL1RINqCaUrXgXE+KFYnylg/XZIZ0Kln+zv4sDttCd4w1yepO5UN1F44Rlw
         GzoP3SMKrPtc/tSpbAFtQc3HwksTO8NeR2HZc7o2L1bsrL0iJ0GcBJTNvkmuC2Q94GbV
         DQzEDGqtCgtRQUBZomB3+AzO7Y/7qmw6okDAJC0E81JFqZ8Yq1eDk3YpFdR5556IFQlK
         gtbjhnwChKB4j2WwF5gBJgCABpKzgtZ9tKXycT9QL+AObHHdLamKLFBpTOafLUphySxC
         0Zj5Cpi1nNPToDRWQ7jZuclNN9sfF6ilekcjEZ7Y8PXtFcD7i7ltvGqMMIWQgZMWsrex
         eM0Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1718319755; x=1718924555; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/AQv1n1/x8DjyJ4L4oNqavGPm1HZT7T617b0URW8QIc=;
        b=ibMy8QPkt9vmZQD8/c3yGMxAoBjVXagLEitN3yZ4jfd7BO0fW+UY8DH9Azd0jPm84e
         ar+Iih+n74njYULh9CZssoLjkByr+SrK0lJO5l2pmh3I0XP+wZlZbzdJKzyve0dkIdcA
         XAMVVg7qFdh8HP63yMLTr1lSEvkO3MifgkcFtb9GhaYr/SyB/GXLl6KsjSEbfM8DrsVN
         w3Tj0Jsgquqj9nAWm6aSfJTDhXd4M8jC8EYt+X9VmQO1yrPLqjIJ7BjwMoWefR6cGXCY
         /4SuMqCS2gS1I++6Tm4qaP8r6jHRP/8ktpuoFyBFGSoDRNLmtJWrrym2ivxumcbE7cUI
         hFkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718319755; x=1718924555;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=/AQv1n1/x8DjyJ4L4oNqavGPm1HZT7T617b0URW8QIc=;
        b=i19i1v9CAD3KiEW54AZl5UsXnMB7xuRDBpRt/tZHs+KppTupPUyRXjSlrzvApFJ9VO
         aV424YdqmcSikD1RYSfc76hefpdjPRA/Ao/04nVqs9t8uucaTPGnFmzfIuNsYxzlwP9H
         bMAoLiOdpSB5jwzPnxezCay6YQIIV7gxZoxyWzAJMvbfEbLeUIEUKblvs3zomMl0ra+4
         TSmc/cU+D1ZT+nytqiV6iRjrHUs48jcg+8dC+xygw40MWt8hhmPCccfE0fkSGW3eex9w
         8PkuyKg6pX4qr2qWvsKft04Wf1HQxKR6O3Fw71R2CNStRsO8q2GwHhfncKMeCnx0YGUa
         T4gg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVIx8WEfmj8IoQ5LxkR53gVgUxJdsdM69n4j9nYBuEwkiTPe3BorRKjHcLJaiN0u1ZHyXOcj6Kk6IrUy6uJa4ay4itew136ng==
X-Gm-Message-State: AOJu0YzBDWsxBHt9QGgsP4YbGpIe5mJ70xbLlBhItJT4N4tH5gt24uTW
	sJSak1NwNPWJMXzaTq1j86IcGaONJks/S+76Vh86FtKKH4ruWS92
X-Google-Smtp-Source: AGHT+IEpiNRkFuQ1DqhYhzcYYgnhNP9KZU5WhVW9XcvrL21uBi9BNyhkUA/dw6kyY4XjGJ+OVkjExw==
X-Received: by 2002:ac2:46e3:0:b0:52c:247d:2cfa with SMTP id 2adb3069b0e04-52ca6e55075mr685310e87.13.1718319754117;
        Thu, 13 Jun 2024 16:02:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:5c7:b0:52c:a0a5:c69b with SMTP id
 2adb3069b0e04-52ca0a5c6eels662644e87.2.-pod-prod-09-eu; Thu, 13 Jun 2024
 16:02:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXBgcvHRxefzQYmXmB2MrDtwMWRaKVfOGI0Ii3fqSPna2hsEnP9DA3p2f6tvSUIykyqoEzUBy2v0nmRG5nNO5/N48d0sqKjJ5vsSw==
X-Received: by 2002:ac2:4c02:0:b0:52c:943e:9ecd with SMTP id 2adb3069b0e04-52ca6e6436dmr717588e87.16.1718319752062;
        Thu, 13 Jun 2024 16:02:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718319752; cv=none;
        d=google.com; s=arc-20160816;
        b=kbbSK7vBtqVwQWvFAf9spjuJbmT1YgUTus22UXAqNbArklqJBJTLlIm1SrU78l13l/
         ECMfFYM76h20YhUysdd3P2wXJ9nAm8SqNeZFS2cNpjvBCrtgjUqz3GlL+EtLdr4kJ6v6
         XNVh8IZrVVLhZmMUjL0NjQWWuunSysMGyQ9X8Z1/t1Zc188+cS+fVFU+8dn0hY7dnnPY
         ycB1pRauHZGumW53+KTNDuhVLGUu82dG242Y9xbtSjX69b8XRoR+3Wsp9aU2UXb86Ewr
         xUB5d9hhpR9hgYKKUEnQwY1+qMxv2Dq13NAFjVr4VsRg0MSUqktyVkx0aGdRTNygjXGm
         T68w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=sXIJpyDlcvNNz9FeS2cMW/4txd/zHy0zvpYr5HA24Tc=;
        fh=W1qD8rQUnAfGjKgrw5TSC/NDzBwTZgEnETenlEdO5U0=;
        b=XMSO/FkQLko+bGA+mr3F3A8o+h40DJNG3lrAxSyH5PsxnmGhdqB1426L/TMsBQRzNn
         W9cQqFjJ9hBJ2bIRXjdaEUaM3N4ebHL5xtzXQw/W2ddHrISmlxjnell3HRI2QmUNOmrD
         sgDXFEgZ6/aBld2vfMBqZDMuhIxKzFDe5gNCLrscPRH6xtyE7IJz/mMq9mb6b4xglZ5e
         vf4/YyBdkZGoJBPY24n9WAJuQQro1xLX+aR+amKScN+73TLgb9DN5AhBNXg4mnJ86cjW
         vf+K+tEYIcy22ksIvjAtjptF9jRS3M2qfHyrmYv018Gz2xaB1f4GCLH1/7YqlOGdsL/7
         FJlw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ahAUtxwm;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::434 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wr1-x434.google.com (mail-wr1-x434.google.com. [2a00:1450:4864:20::434])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-52ca27c60e5si53340e87.0.2024.06.13.16.02.32
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 13 Jun 2024 16:02:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::434 as permitted sender) client-ip=2a00:1450:4864:20::434;
Received: by mail-wr1-x434.google.com with SMTP id ffacd0b85a97d-35f2d723ef0so1478578f8f.1;
        Thu, 13 Jun 2024 16:02:32 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW+3qaT3zS30FZppOnnh85G2OeBrUzoK8LCgc8fJlrqujB+eYblo/RhZMnydbfJo71yXDNwRQ7LxP3CTdatLzJw3CSGfB4+OVWNpjhIiCQXyPkZXxcYpPZlt1SjfZoSkIEJox4HWAM=
X-Received: by 2002:adf:e256:0:b0:360:81c3:689c with SMTP id
 ffacd0b85a97d-36081c36a40mr190889f8f.7.1718319751207; Thu, 13 Jun 2024
 16:02:31 -0700 (PDT)
MIME-Version: 1.0
References: <20240611133229.527822-1-nogikh@google.com>
In-Reply-To: <20240611133229.527822-1-nogikh@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 14 Jun 2024 01:02:20 +0200
Message-ID: <CA+fCnZdfB206Bjw=MAkZ9qbKUtf-KeGrrqJnOJ1ZrgH6fGXRhA@mail.gmail.com>
Subject: Re: [PATCH] kcov: don't lose track of remote references during softirqs
To: Aleksandr Nogikh <nogikh@google.com>
Cc: dvyukov@google.com, arnd@arndb.de, akpm@linux-foundation.org, 
	elver@google.com, glider@google.com, syzkaller@googlegroups.com, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=ahAUtxwm;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::434
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

On Tue, Jun 11, 2024 at 3:32=E2=80=AFPM Aleksandr Nogikh <nogikh@google.com=
> wrote:
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
>         KCOV_MODE_TRACE_PC =3D 2,
>         /* Collecting comparison operands mode. */
>         KCOV_MODE_TRACE_CMP =3D 3,
> +       /* The process owns a KCOV remote reference. */
> +       KCOV_MODE_REMOTE =3D 4,
>  };
>
>  #define KCOV_IN_CTXSW  (1 << 30)
> diff --git a/kernel/kcov.c b/kernel/kcov.c
> index c3124f6d5536..5371d3f7b5c3 100644
> --- a/kernel/kcov.c
> +++ b/kernel/kcov.c
> @@ -632,6 +632,7 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsig=
ned int cmd,
>                         return -EINVAL;
>                 kcov->mode =3D mode;
>                 t->kcov =3D kcov;
> +               WRITE_ONCE(t->kcov_mode, KCOV_MODE_REMOTE);

Looking at this again, I don't think we need this WRITE_ONCE here, as
we have interrupts disabled. But if we do, perhaps it makes sense to
add a comment explaining why.

>                 kcov->t =3D t;
>                 kcov->remote =3D true;
>                 kcov->remote_size =3D remote_arg->area_size;
> --
> 2.45.2.505.gda0bf45e8d-goog
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZdfB206Bjw%3DMAkZ9qbKUtf-KeGrrqJnOJ1ZrgH6fGXRhA%40mail.gm=
ail.com.
