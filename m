Return-Path: <kasan-dev+bncBC7OBJGL2MHBBYP3TTEQMGQEOB7HPLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id C729AC8B551
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Nov 2025 18:50:26 +0100 (CET)
Received: by mail-qt1-x83b.google.com with SMTP id d75a77b69052e-4ee09693109sf1734981cf.3
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Nov 2025 09:50:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764179425; cv=pass;
        d=google.com; s=arc-20240605;
        b=W8UsHDLzGicHKVqXar3iYqx5nLtObTtejskoWdpn8VZBttFPeRwpdiKhrqVS1Jbs/g
         sRA5uxZclbxF0yYUrbszOsuKjEa2S/FeZbSFS0KGuC1I8f+02FkLDC2M6SUk4lCQWQu0
         6fS4Qx9jrR7uZ2yB8TAdFnU4/uYnlFzdlteEK9KDfkDD6LR1WDcP3C6Wr75D0zVmA/1R
         vj08iVVORtuOhfb0cmU5obzxUFdUVOSgq61Hijops9uvHlaeChiiGm9jYRLIp2zzjzcd
         qDzLo+1vAQymktaMzZAuEF5h1SvosxAxRreKPAvbPkuHIFkUBUCMuoNIxqAjdCaaCGfA
         BZww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=elGQxflMFlIk9Ov9HOBSmJGFmWpZzRjZYTVd03mwjXg=;
        fh=WhA2Wslw24sxQrLnlnzbjAgTMIV4ror35lHXXe+w3gw=;
        b=QDETyTpAu6EILmfZ/JZkekLpPe8fa+wDcq67aaxw/UiH8Um1o8aiYs2YlgscsOhNkW
         XK+midNaeRQI/hD5gbLJX+ojQeUTiFWuvvEBEKdQNR/tVeVHeJuU2JHdhD9pA+ZO/DiL
         FIvy/CENQ3m89tEmTealfkP5pseURRq3fnHC21N/HLn/1RQBkFxifAM3JiALbyQGUHjl
         8vNzGjiu0qdWqDOVZ0gBaiAoypAkoDztPT2gnvd1xivXn3DM4dJy0RUse+LRwXa+uq7B
         ocZke3yfsat9FFub99ROlmGenRXmNg0B/3mKs0+DTB85lAhJN1zkSEpiQHHptMXedIlQ
         YVaw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=nEXXJrTo;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764179425; x=1764784225; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=elGQxflMFlIk9Ov9HOBSmJGFmWpZzRjZYTVd03mwjXg=;
        b=N3RHoK5aDC0VgToAzkhiU0IzZrFXx6qqbQQuG3+blRcuETrN0Sknw70cV0qRBtlppf
         Fzvq6Ut2mUwUrILGFYuZlPVfsI8IK+e/VcPfH3aHyZdt4Hgp4Zxw33GN9ffplQhHK7zY
         vpYddhTUt7YuSDiM9mqV5LFkdITqXP+HBOxxmNVQNrM+z2cxrjBRhQVOndi1GgxyqOR4
         WZkrwR/f8P1SZ5Bdhst+iLfGobbAQUkdKl4kKRT4Cqc+7be4hPxA9iVfcarjnuN1B5NE
         BnuUevQSCO/zJwBCCZP+ihmNgOMR34ifNBzXLgX31lJkGyDxDUyc2JJeFi7h2+LOwjp/
         L+kg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764179425; x=1764784225;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=elGQxflMFlIk9Ov9HOBSmJGFmWpZzRjZYTVd03mwjXg=;
        b=v5QfQIaMcE2BCExTdmncduv6X8TcgBOpjopp9QaJKkdqmppvk3k0U3ElG8Iz7Xh5NZ
         GwWiRwbRtghwFpytGojfwWaaaEmy0DuDdsSgjBp4Ia6gRQDt5xyOAHir+IH0qhQ1St6r
         nRzf1tGzwdYrgXPHsmRUFIgEfR1+n//605D7rQN0cNi1YT3lCVrHMBqILCRJ1TvAv1ql
         p3XkgbiO/6+WS2NnWFJmGy22mRLpZAgloLH3oP+J0bTnhDzLok30vvFOy4P1VdP1OnjL
         8U8ihpY0s2pdA9M4+NG1/dqFDY5GAMt9VyXvn0g+9KWD+/21xj0LBgwWYFsQwo2geGzT
         p+xA==
X-Forwarded-Encrypted: i=2; AJvYcCWlxlfuuIhj8h4amtR9dTCE++Rogm5GDX+1Nqwirlpa44M09+uPplwQ0GzQ8UAYR305qfJScg==@lfdr.de
X-Gm-Message-State: AOJu0YyvlXk3cd8MNKs9rnkE34NV9WmQVSaiSAxT5PxYgtvbv2mKYZQr
	8L2Z6iWzmZNLD/6ZLI2JBoXtLhrNWHHUki7tKixxl4B9TB2zLcEsrNYo
X-Google-Smtp-Source: AGHT+IFW2D+UGgF38TYA/GPpgrJLbeqD9d8UC82sAk4P5fj8I0aSSpcloc3YQjvMLn6Zc8puxKyX4Q==
X-Received: by 2002:a05:622a:4ce:b0:4ed:b55a:6b2b with SMTP id d75a77b69052e-4efbdad7698mr85754941cf.50.1764179425566;
        Wed, 26 Nov 2025 09:50:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Zdfyu2EypLHmwH74S+XPP70l+037HGXCVnIB8I3ODY0A=="
Received: by 2002:a05:622a:4f:b0:4ed:76f4:e4bb with SMTP id
 d75a77b69052e-4efd0332593ls2148341cf.2.-pod-prod-07-us; Wed, 26 Nov 2025
 09:50:24 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWu9rh0oVjkrdXj+dDRuiCW00Kja+BNLUMMbjpQomesUNJq3tSpGpM/zDgdFjsolBqgl6guW+26TZI=@googlegroups.com
X-Received: by 2002:a05:620a:19a9:b0:8b2:f0be:27e4 with SMTP id af79cd13be357-8b4ebd545a5mr1007688485a.18.1764179424443;
        Wed, 26 Nov 2025 09:50:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764179424; cv=none;
        d=google.com; s=arc-20240605;
        b=elFG4Q6Ju2Zjyqgl1+6aiXsNdbUPnGNZR3ZIlR+pZiItnq50Dl+M0lCYEXRbPsyfwS
         tuAJ2HGE8mXF3qvnoFhQM2LQ+h7uCbW2iCNffTsUPvpZ9KJhMBhLGlDwqNlxI+OuqJud
         MZUlZIC8mZKe8Msy0PXFvNdqsoi5P8C02XXHjfT4lyyDldwdesHw9dfvA/cI1exDz9Gi
         T09adz46BShjUVcn+q+nsfcOx4MfLT2ptIUncnZcyLsJ3F4Jtnf1TDF6TyDw9yKX6eXJ
         nVju0JIPDwjuWiTr9E9Xs58On0qu7wHs3g7Hq6m2XQAJN2qssZVO7orLg5UA56zgCeZT
         IuHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=59kXixxQWJbDiB8ZH4iPSjqxruE37/qXgYYUaXC6aUg=;
        fh=FJTiOEeGg0Lsp4r0ZJ5imld3H2Jrr2zS0Q67veUdw3E=;
        b=GqqE9gGOcBC+3N02cZThvranPxLRuoL1h3QOxKNPwnTun+tfU1s3QKYvlgO7jindFP
         EDCI/i1wn4wI8yWLqUayOipqKNf/Iek6EYwKiTBpsovHJS6Ot3UgROEXjT9FmgNFU/wZ
         N8/N3fsmtrCx6lYB2aKCctD9qJFHUtp4A5JDU06539DxPtbAV1ug/kETuUcZopy7wR0I
         719dLN19cZ+xVtsWVh8z6W20o6Ky5BzZcfHYY3IE/zk/J5ZNAqD3fciDlw3AFDbCf8fh
         rWQpXH0Uo8vNIxYdITSOauGTyFqNJx2BIVDluaZJRk0NKly58/dtVwb8g2IsY4fDfpQE
         iSKQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=nEXXJrTo;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42b.google.com (mail-pf1-x42b.google.com. [2607:f8b0:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-8b32942e566si66407585a.3.2025.11.26.09.50.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 26 Nov 2025 09:50:24 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::42b as permitted sender) client-ip=2607:f8b0:4864:20::42b;
Received: by mail-pf1-x42b.google.com with SMTP id d2e1a72fcca58-7ad1cd0db3bso6125500b3a.1
        for <kasan-dev@googlegroups.com>; Wed, 26 Nov 2025 09:50:24 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVhc7+UTHa9WVfSdYOOyNbkPyD0uwjoE2IdaO3q/mgr4kNOQGRGVDw8luTN32WVBtj/VxVRDLAD6eY=@googlegroups.com
X-Gm-Gg: ASbGncsecxcfVW59ibUveRrgL06/O9baRQt+ULdzpeCUWD80bQitZlDDI5IzgrkwVl/
	y6oowlmas4WH/Xz10scD3q4Pf4LhUf7ls/o4p13VpBDKWIsOB9kZtusDUqVIyzvSkSr3lTut0Iz
	Z0+1U2iFC9+ngY5AYsqxdGuONam88zjE/+lWfTX7pXItD2m6PSZU5hBtHFmnOm+uu/Xiy6w8SBU
	3oSxdwsNd2Khnq006uLVbnOB29E8rPDfGQfzC1e0l58oiFSEveWIVxj2mAfFawYwdYLlttwl9Ki
	SEv5c2JeaZMkzZd8gzfqB02vig==
X-Received: by 2002:a05:7022:1607:b0:11b:c86b:386a with SMTP id
 a92af1059eb24-11cb3ecc9aamr3576458c88.5.1764179423189; Wed, 26 Nov 2025
 09:50:23 -0800 (PST)
MIME-Version: 1.0
References: <20251126-kfence-v1-1-5a6e1d7c681c@debian.org>
In-Reply-To: <20251126-kfence-v1-1-5a6e1d7c681c@debian.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 26 Nov 2025 18:49:47 +0100
X-Gm-Features: AWmQ_bnJoMrdDOqPDJnxQjbPC977DXkSYeKKnQxtfcjlsJnLvzh-SYYPHrqcVHY
Message-ID: <CANpmjNMmw366KEUnu_OQKDKvZJQErj2mXe7TxyQHObvpHjt5hA@mail.gmail.com>
Subject: Re: [PATCH] mm/kfence: add reboot notifier to disable KFENCE on shutdown
To: Breno Leitao <leitao@debian.org>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, kernel-team@meta.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=nEXXJrTo;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::42b as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Wed, 26 Nov 2025 at 18:46, Breno Leitao <leitao@debian.org> wrote:
>
> During system shutdown, KFENCE can cause IPI synchronization issues if
> it remains active through the reboot process. To prevent this, register
> a reboot notifier that disables KFENCE and cancels any pending timer
> work early in the shutdown sequence.
>
> This is only necessary when CONFIG_KFENCE_STATIC_KEYS is enabled, as
> this configuration sends IPIs that can interfere with shutdown. Without
> static keys, no IPIs are generated and KFENCE can safely remain active.
>
> The notifier uses maximum priority (INT_MAX) to ensure KFENCE shuts
> down before other subsystems that might still depend on stable memory
> allocation behavior.
>
> This fixes a late kexec CSD lockup[1] when kfence is trying to IPI a CPU
> that is busy in a IRQ-disabled context printing characters to the
> console.
>
> Link: https://lore.kernel.org/all/sqwajvt7utnt463tzxgwu2yctyn5m6bjwrslsnupfexeml6hkd@v6sqmpbu3vvu/ [1]
>
> Signed-off-by: Breno Leitao <leitao@debian.org>

Looks good as discussed in [1]:

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  mm/kfence/core.c | 24 ++++++++++++++++++++++++
>  1 file changed, 24 insertions(+)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 727c20c94ac5..162a026871ab 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -26,6 +26,7 @@
>  #include <linux/panic_notifier.h>
>  #include <linux/random.h>
>  #include <linux/rcupdate.h>
> +#include <linux/reboot.h>
>  #include <linux/sched/clock.h>
>  #include <linux/seq_file.h>
>  #include <linux/slab.h>
> @@ -820,6 +821,25 @@ static struct notifier_block kfence_check_canary_notifier = {
>  static struct delayed_work kfence_timer;
>
>  #ifdef CONFIG_KFENCE_STATIC_KEYS
> +static int kfence_reboot_callback(struct notifier_block *nb,
> +                                 unsigned long action, void *data)
> +{
> +       /*
> +        * Disable kfence to avoid static keys IPI synchronization during
> +        * late shutdown/kexec
> +        */
> +       WRITE_ONCE(kfence_enabled, false);
> +       /* Cancel any pending timer work */
> +       cancel_delayed_work_sync(&kfence_timer);
> +
> +       return NOTIFY_OK;
> +}
> +
> +static struct notifier_block kfence_reboot_notifier = {
> +       .notifier_call = kfence_reboot_callback,
> +       .priority = INT_MAX, /* Run early to stop timers ASAP */
> +};
> +
>  /* Wait queue to wake up allocation-gate timer task. */
>  static DECLARE_WAIT_QUEUE_HEAD(allocation_wait);
>
> @@ -901,6 +921,10 @@ static void kfence_init_enable(void)
>         if (kfence_check_on_panic)
>                 atomic_notifier_chain_register(&panic_notifier_list, &kfence_check_canary_notifier);
>
> +#ifdef CONFIG_KFENCE_STATIC_KEYS
> +       register_reboot_notifier(&kfence_reboot_notifier);
> +#endif
> +
>         WRITE_ONCE(kfence_enabled, true);
>         queue_delayed_work(system_unbound_wq, &kfence_timer, 0);
>
>
> ---
> base-commit: ab084f0b8d6d2ee4b1c6a28f39a2a7430bdfa7f0
> change-id: 20251126-kfence-42c93f9b3979
>
> Best regards,
> --
> Breno Leitao <leitao@debian.org>
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMmw366KEUnu_OQKDKvZJQErj2mXe7TxyQHObvpHjt5hA%40mail.gmail.com.
