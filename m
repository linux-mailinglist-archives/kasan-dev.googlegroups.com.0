Return-Path: <kasan-dev+bncBDRZHGH43YJRBUNX576AKGQEWJDQKUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 14FFA2A0153
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 10:24:36 +0100 (CET)
Received: by mail-pl1-x63e.google.com with SMTP id g10sf4098730plq.16
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 02:24:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1604049873; cv=pass;
        d=google.com; s=arc-20160816;
        b=aTNuUtgJz1PaHagdIZUxHiTdiZEybgCnTclK4XHuTA1/82wQR9wERUoGwg1kZxysd6
         aWZYgnhAic69pw0mUZnn3dW6kETduSodki7QvAvQtiQNe0uWEibwWbEhI1bffGLXYrlT
         n+LeJKXMXQwPGHJbVh2HDRC5MfBPa6L2rPSXRWwtXf+qFQorc0iRJjDtnOsGyvsUareP
         rnAV7D4pSdsyH6QPPVJsZIG2f7puCY6aycQCDQTtptW9fXIcj0bJEQT2WFiF1edKau2l
         oSZMT2yooFxIf+Jpv1XnOCw4l9VFH0QsfhTqL89D1kKmgoztATNhp9Zyim/SdchuiN5o
         Fo7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=zKqopYlXyK9YdgK+/0tsu1lU60urOlQD/56CdnQXoz0=;
        b=ZuDoyWtUup0uzrRb/bahwif6SQa8t0Pbhu3jBh8fK1NH1z9b3Cyh2+3jlbRKD/EffV
         fNlIPDz3FmPUbRpg2IY8JPCszRlrNrnvyGhQ0fkBG6GX3TmNqeGJgi57if+EvsFFuunA
         de73R+/760gd8I0zTMR64CFkooHryxuwFu7iV8cbqiNma2NFlGkSshQNlzTSc3ZVXRWD
         lBuPEvDnBlup/2Gg7PrOzwBB2m/dp6ml92E59H2eRX3ChKQmnLm+MerC1kdVm8hYa7SP
         7sE30wh/YMpOTxaTkqQPJDolCasP+DhZvHlw+0jYCpWI5NM49wBMxBn7dUdYr0WZgeOV
         v37g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=uR+S+1eT;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::b44 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zKqopYlXyK9YdgK+/0tsu1lU60urOlQD/56CdnQXoz0=;
        b=o0cf5Eu2LrtpNFJCSiafoCqYwN2QKATwAurW8RcPuGqA1zlQkOjvcVYsUdGSiGDROH
         FqcCIplFDLND+sE4t1kiZB3xfjfb0hWs2Sxt/uyKl1RZuXAn7w2x8VDarWzApJHslaYq
         Seca8yNRIKrEWMwQor6DvSXcBEfUJV5jn46W54AvOGzzDOjYzaz6AmR11frKTAQqLKi1
         2zJWsejUHk6WkBolrg7zRAz91cBWdXIey9oOW/NY8jGz6cEznGqWAUmcS8wuhk8/9iux
         J9Se79/yDHupgqpHIV4LYwvU5ost5l1xASAW/seHuIw14on3hYmeJl5OgfF9+oyZwxmt
         5AFA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zKqopYlXyK9YdgK+/0tsu1lU60urOlQD/56CdnQXoz0=;
        b=EYbTVRzzGJJPefmZ+tRG6UkOfSj+7w8JeSvqAzXL7bCfWDEdYpsmW7nUaSzKyLfsJV
         CbO7gydvlWQ7F8+F8G8TFwnQnbZTWDjYyxlV1PW6DNZof4HP0sS5w2aKIkKyrDALYW5O
         8Z69h4dA4kbXm7e3U9rDwS4GoP2KPzyOGxTRKIh0NZfG/qNF7ZpZ+akhsjWaayvioD5X
         JdMAGae/BtGT+By9TA98+8TturWy6BPD9itur0C7RWn8AIWw4D8zKFm+IZejSpz9veTr
         FOkFDYgwoBU8fbOwU9CECvJep3thLPQ0ADhK5VMG5afyDGsx9wLlZwdzOzIczHyARylB
         u+gA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zKqopYlXyK9YdgK+/0tsu1lU60urOlQD/56CdnQXoz0=;
        b=B8wR0mFH0JwnTOQ3mL920xNTyW0KVeeeQ64BBDOrQKV3ijRk83aAj1oPRN4kFVLdSH
         gbfrZrZtq/LwgaBti7tyqLpNg3rmhAmpHrLM4WkoTIVMag9VCMiKamkUmpk6JWRwwpF+
         M3I3pBmPZLGM+hwPnTN39kSW60mnX85YIEDCGBB5CLIIvYeTPZHzJmNRx7f889ZezWDe
         nmfPNBM0ngSPzCtGivz2mF8u0I/3QcwwmIPmxaUTkkga4o6v5PjqOFYlX7ZDlNuVU+p2
         wM06HAofd+QcCEwKhR7VDzM2bExSYdnpjvEWbuqjfXetxaCz7MahfrpPs8nqtPNIuVZ6
         uhjw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Ib1bwecHiwv2gy/2/3Rmv2frSNCo2DRJgVx5Z1SXfAjmEx2Zd
	WnQRNT+luNkcWwVLniyogss=
X-Google-Smtp-Source: ABdhPJwns0gHlN8VQXCYc/Xs5LazX8zmR24N3VRTvCixDTdI6MQ4wJ3TV4zzbPBGv7I/XNDBGem0gQ==
X-Received: by 2002:a63:f20:: with SMTP id e32mr1441547pgl.61.1604049873520;
        Fri, 30 Oct 2020 02:24:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:ae08:: with SMTP id q8ls2143613pff.0.gmail; Fri, 30 Oct
 2020 02:24:33 -0700 (PDT)
X-Received: by 2002:a63:5914:: with SMTP id n20mr1404617pgb.69.1604049872995;
        Fri, 30 Oct 2020 02:24:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1604049872; cv=none;
        d=google.com; s=arc-20160816;
        b=ervOqonL/DwZ+0xyn6WjZAKLxxjTUNh6/JqvYZcjgYu3BFLMhjYfx622/XieZKV8eW
         8k8darIN1qpuNf45cw/b9oiOng+nLtTfpU4M497oC5K2Ftn/Fjrn1/LRcnF2SHMVyV/h
         dxioDwjZ6yZoL/gY9Y79Um73Zfsnmgdln3Noers1nDdJnn2LPpCzBjqdLOdbMjgNPnI8
         joMft5atzakBBW7Ahd4DtJrsatnF6vuIMn3cIFy6bvJ3DGxbvipxUUQwfbSbb++4kzOu
         Zwr119917awitBHYm/+kXs4onQiosHUp5mEKbDw9JWROZ7+LgYjSp+IxGgMhz1Q3OAza
         Xa+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=AT9nl2GUPzLTlSYpK+8OlDbwytVPpP6cQwtdlWueTMI=;
        b=0Q6u2hAwBJN7jyF/OtyG4sDED0+2uBEZSK4s3eP7H3emCNoeZgdIyxFya//WAJpOFG
         xxO38CHBXH1EQ6xTelah0cA6wz4ZNK701OK7LEdCOupZVL9doEEO+7H3kE97KorgF1hB
         kq4Qf3DM2iyLNgkckRaNOCV9vJ/6YozDMbX0lRkECAgctXv0vstIrNgpezwGo0qaTccD
         V7z8vuXdoNfFdKnRh3RlVQkO5Uob1KatjzRgkK1SI1ZstTwYa3s3RCMt3ebnDyci1cdK
         QJ9uSAzLaxAWjOc+XOgsEXsQCiziA5THhDsfWEr4oKe1ogO9RRItefKihEQvC3wXB2YG
         m4mw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=uR+S+1eT;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::b44 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-yb1-xb44.google.com (mail-yb1-xb44.google.com. [2607:f8b0:4864:20::b44])
        by gmr-mx.google.com with ESMTPS id l11si413876pgt.3.2020.10.30.02.24.32
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 30 Oct 2020 02:24:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::b44 as permitted sender) client-ip=2607:f8b0:4864:20::b44;
Received: by mail-yb1-xb44.google.com with SMTP id m188so4575754ybf.2;
        Fri, 30 Oct 2020 02:24:32 -0700 (PDT)
X-Received: by 2002:a25:d441:: with SMTP id m62mr2320037ybf.422.1604049872377;
 Fri, 30 Oct 2020 02:24:32 -0700 (PDT)
MIME-Version: 1.0
References: <8451df41359b52f048780d19e07b6fa4445b6392.1604026698.git.joe@perches.com>
In-Reply-To: <8451df41359b52f048780d19e07b6fa4445b6392.1604026698.git.joe@perches.com>
From: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Date: Fri, 30 Oct 2020 10:24:21 +0100
Message-ID: <CANiq72nXkHeF26vY7EK5u0h8pFXwWq5YUUcSHDULvgh1caCNGA@mail.gmail.com>
Subject: Re: [PATCH] treewide: Remove stringification from __alias macro definition
To: Joe Perches <joe@perches.com>
Cc: Linus Torvalds <torvalds@linux-foundation.org>, Ard Biesheuvel <ardb@kernel.org>, 
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Herbert Xu <herbert@gondor.apana.org.au>, "David S. Miller" <davem@davemloft.net>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Nathan Chancellor <natechancellor@gmail.com>, Nick Desaulniers <ndesaulniers@google.com>, 
	Thomas Gleixner <tglx@linutronix.de>, Borislav Petkov <bp@alien8.de>, 
	"maintainer:X86 ARCHITECTURE (32-BIT AND 64-BIT)" <x86@kernel.org>, "H. Peter Anvin" <hpa@zytor.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-kernel <linux-kernel@vger.kernel.org>, 
	linux-efi <linux-efi@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Crypto Mailing List <linux-crypto@vger.kernel.org>, Linux-MM <linux-mm@kvack.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: miguel.ojeda.sandonis@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=uR+S+1eT;       spf=pass
 (google.com: domain of miguel.ojeda.sandonis@gmail.com designates
 2607:f8b0:4864:20::b44 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Fri, Oct 30, 2020 at 4:07 AM Joe Perches <joe@perches.com> wrote:
>
> Like the old __section macro, the __alias macro uses macro # stringification
> to create quotes around the symbol name used in the __attribute__.

Hmm... isn't this V2? It seems none of the Acks/Reviews were picked
up, did something major change?

Cheers,
Miguel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANiq72nXkHeF26vY7EK5u0h8pFXwWq5YUUcSHDULvgh1caCNGA%40mail.gmail.com.
