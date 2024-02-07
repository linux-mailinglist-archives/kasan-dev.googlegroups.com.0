Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKMNR6XAMGQEF5D5M6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 0357884D09F
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Feb 2024 19:06:35 +0100 (CET)
Received: by mail-oo1-xc3c.google.com with SMTP id 006d021491bc7-59a6d6c51c4sf888185eaf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Feb 2024 10:06:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707329193; cv=pass;
        d=google.com; s=arc-20160816;
        b=xLGgK19qHomKx062rbgBimuKJ9CmU0kFpAHiX/4d5oAvAYLKnOyQJ7/shOBrJ9bdSU
         QlyJ0+OTXomWZ+/ZAaNfzUvBLRLjwSJx0Y6GexlYC/A6Kqrk13E4v9AMdI6nKZDMEmoh
         3ZaxjWi6fsergGX/9RntaYA7mtMhe6qB/e7ZRXy89wSUND6HgCPGlui31YQ2VEyWrYWF
         Uh4TGgTgV9b14bSP26Rm3jq5hMyqGr3Q2OTY2AWiVsEBD0mc9sBHB5gBko1fjG04ILEl
         g/0GGDUlOf0XH3PrWo3kLnw5gPcXsrqyhL9jI1o447wDLMAoYQ2ZCLR9TlzvvIN6tlUI
         c+zA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=TAjwuOIndISvYohJEfNMlZgp7GOZS5XrrSZu9Ei+p3E=;
        fh=6gUlu/bAzyQ8EU7HFNTkYxWkTNTt8uCveC5LuPHe0YY=;
        b=ssXWH0UL6u9mOs+SSuhqPXKgZ9MnMtXOwJrjEIspphUO7V0o39t0u6a8LKgP1DoONL
         wBn4iSh4Bp6Q789IjZpI90Wd1KWb1UgL07jq40GhNenSfxkQVuY6Xs8NOvEUrc4pY8D6
         +39O6cQvH6S6CthNn/ine0gYiibd3Yc+/qF9zYKWigrJqolTQqd3IIfc3z5uUTwn9kwV
         vQIsQVUoLFs4BM5cPSHg2RlCvmGHQIl1oXy0vxqygGXQKJez3+Zz4d5xAUJ7dWsznCOA
         D12n7i/40v0lkIvH5Fu0FXuaD/wrT4oQPto7nqXE34VSVB4HoWI+XF7CKknMk76+4v+L
         sOng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=F6LYUSHn;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707329193; x=1707933993; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=TAjwuOIndISvYohJEfNMlZgp7GOZS5XrrSZu9Ei+p3E=;
        b=qUK0VU8/3y5ovPeZl95aNGqVFE/eSLdbkfyE5ZGdlSXkMXIgYRxTkZRvRL7f4x/BRY
         PSyPRWEUih80/0FfMOpd4urXLIOxnczh5KvlotJnesZ6TbbXS8YAVVcv9MXl6gB0mm7O
         bIQLXyJ/udNMLFqxHAD7jr9GZ8gDs3x5fkHPB3T5wn0PZFDQPncRAzYPcE3P52nfHKGZ
         SFmpBdMIWfbuwy4mCmabRsEc+GZwj980mKDZ4OiPe09UVU2xkRlMvHEAIV2TkIG2bhON
         ieGl7qQVV3yfuzAHmf5M10gilO1IbNPBlG+oQxJy9DhuTZjMtxYYUm+lNGO3sCpZZ5ZS
         0KUg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707329193; x=1707933993;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=TAjwuOIndISvYohJEfNMlZgp7GOZS5XrrSZu9Ei+p3E=;
        b=suTUS3TyzLTNQFcjxlvFlsw9tVFF/RHkZUM7eGyBxmf+8L0XLhALNzMCXB337A29JD
         pHu1WCwNQnQRRtrt4jZesU61K8AwWZ7l0YuT/zONh035rZIiF1ssdb/27i6uTlUYnQ3+
         o6xKwOTusK5jPCf1ZUOMKwHZjra5wIX7gbs/3Jr+JyAZCiVD6XOYJhEuDEv3gJjZrhYV
         +tHV1yPPN9rtvOMOGsaZyQNTUhH+dz49PAqxx5MIHBYmwb4qhb9HZZUvH3XfW4axYGFF
         NIZSR3z9e8PkbIYI9j3Ktvmy1yuXl3NWbQ2oD/ejavTWe/cvYRQ06muTuiwfRm8fhW9K
         ZQDA==
X-Gm-Message-State: AOJu0Yz3kEVZZG6g5je/6gSYQEV8/Vc2GuSrw6EslkZ/QtBXO/+5q+NU
	tEEwO6w9qiDOue9dcbaQqoA4VzdXxPKvJgEEoOlZTzWhWGEoOPq6
X-Google-Smtp-Source: AGHT+IEekiE4eNrihPC9CPojZl4W9upaYirkGJQGtpbYJnIQmTQIM0rGajVN1aJY1qLnvxU7wmDHoA==
X-Received: by 2002:a4a:651c:0:b0:59a:96a1:dd0b with SMTP id y28-20020a4a651c000000b0059a96a1dd0bmr6681098ooc.5.1707329193426;
        Wed, 07 Feb 2024 10:06:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:5804:0:b0:59a:98a2:b1f4 with SMTP id f4-20020a4a5804000000b0059a98a2b1f4ls1122636oob.1.-pod-prod-02-us;
 Wed, 07 Feb 2024 10:06:31 -0800 (PST)
X-Received: by 2002:a05:6830:110d:b0:6e2:b6d5:d0d8 with SMTP id w13-20020a056830110d00b006e2b6d5d0d8mr3178968otq.37.1707329191422;
        Wed, 07 Feb 2024 10:06:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707329191; cv=none;
        d=google.com; s=arc-20160816;
        b=vZB13vQf6LlpYhAEJ/mBwpUs9ZzbTsPE2KuAVaWsrvOIG0bK6R9agf7qvm0N3tlGpM
         Xq73qBvgWwxHT+ycYZeB3kbOsrwtBNVFa3bcA7SIfZxcca1EkD01ZPSh5dfl/inC0du7
         FHPDpaQmCeIsyU3UiyhQuH3urGgHtg9CcHQWBEcqzE3zN/7076Wfc+NvcUPZ8nfLRUyw
         GO9uvVyZglyZw56pP1nHds7w3S2Z6CwwmbKAOIABgs8t7G79Wj90PGiIE+q6J55T4rof
         grcMbN3WhHavo+nnDKk9NrFLFhIyNjTP8DYTUZfBIEx1uG5aBXzhnz7f8/5E8UfSVtZa
         PazA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FbPnNAGdA+Z4vkIjVqGfUek4LBzvBXvj6UQfxJdNe4k=;
        fh=6gUlu/bAzyQ8EU7HFNTkYxWkTNTt8uCveC5LuPHe0YY=;
        b=b89VHehPRrl6CNAYgoeGTPigZdNGJ4hjOLKijyd+tfl/DxNvBJ/wP7GrcAVw2UazVO
         JwR35XOlkf4UCBan62X6Cza7HFCFlHw6z3LTVVJe/rT1fsId6NcQhzlro7AaIu3BV1/V
         JfIMWqNvOg+btSZV5oeDO58JNzgr6DwIS823JHx8DeHZeoyGBq4pKOgq+2+rOnOAiJqr
         ALwGVIHBxzjf9r5eWhG6RuomAzLuxrS3fvqNFVn8FM4SvDVExfEidjrKsSYy7tfEImOu
         G9+vzpxzUABxBHAZ2P6Nu3qaYgXGurBJRYreGz5X0DPfxgkL1+6rInmn49aCgTTNmJIU
         Y5LA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=F6LYUSHn;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCWVmnyFZ+Xt+hichdOxDbk/GVhO9ec3uXiFcNzUDaRxYoOgzm47KdwZy4kOxgtdYxudhX1XQAYcA69YK+PL16R2H1OgpRqYm2j4jg==
Received: from mail-yb1-xb32.google.com (mail-yb1-xb32.google.com. [2607:f8b0:4864:20::b32])
        by gmr-mx.google.com with ESMTPS id q9-20020a056830018900b006e115ad53bcsi180688ota.1.2024.02.07.10.06.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 07 Feb 2024 10:06:31 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) client-ip=2607:f8b0:4864:20::b32;
Received: by mail-yb1-xb32.google.com with SMTP id 3f1490d57ef6-dc6d54def6fso761583276.3
        for <kasan-dev@googlegroups.com>; Wed, 07 Feb 2024 10:06:31 -0800 (PST)
X-Received: by 2002:a5b:609:0:b0:dc2:1d13:2f4c with SMTP id
 d9-20020a5b0609000000b00dc21d132f4cmr1820152ybq.46.1707329190680; Wed, 07 Feb
 2024 10:06:30 -0800 (PST)
MIME-Version: 1.0
References: <e2871686-ea25-4cdb-b29d-ddeb33338a21@kernel.org>
In-Reply-To: <e2871686-ea25-4cdb-b29d-ddeb33338a21@kernel.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 7 Feb 2024 19:05:31 +0100
Message-ID: <CANpmjNP==CANQi4_qFV_VVFDMsj1wHROxt3RKzwJBqo8_McCTg@mail.gmail.com>
Subject: Re: KFENCE: included in x86 defconfig?
To: Matthieu Baerts <matttbe@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	Netdev <netdev@vger.kernel.org>, Jakub Kicinski <kuba@kernel.org>, 
	linux-hardening@vger.kernel.org, Kees Cook <keescook@chromium.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=F6LYUSHn;       spf=pass
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

[Cc'ing a bunch more people to get input]

Hi Matt,

On Wed, 7 Feb 2024 at 17:16, Matthieu Baerts <matttbe@kernel.org> wrote:
[...]
> When talking to Jakub about the kernel config used by the new CI for the
> net tree [1], Jakub suggested [2] to check if KFENCE could not be
> enabled by default for x86 architecture.
>
> As KFENCE maintainers, what do you think about that? Do you see some
> blocking points? Do you plan to add it in x86_64_defconfig?

We have no concrete plans to add it to x86 defconfig. I don't think
there'd be anything wrong with that from a technical point of view,
but I think defconfig should remain relatively minimal.

I guess different groups of people will disagree here: as kernel
maintainers, it'd be a good thing because we get more coverage and
higher probability of catching memory-safety bugs; as a user, I think
having defconfig enable KFENCE seems unintuitive.

I think this would belong into some "hardening" config - while KFENCE
is not a mitigation (due to sampling) it has the performance
characteristics of unintrusive hardening techniques, so I think it
would be a good fit. I think that'd be
"kernel/configs/hardening.config".

Preferences?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP%3D%3DCANQi4_qFV_VVFDMsj1wHROxt3RKzwJBqo8_McCTg%40mail.gmail.com.
