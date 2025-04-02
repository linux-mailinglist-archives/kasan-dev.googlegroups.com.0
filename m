Return-Path: <kasan-dev+bncBCCMH5WKTMGRBTNCWW7QMGQEJM7THUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 1890DA791BD
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Apr 2025 17:01:36 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-227ed471999sf106861265ad.3
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Apr 2025 08:01:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1743606094; cv=pass;
        d=google.com; s=arc-20240605;
        b=dHFMAx9xvKXmt9+da3RqYKFdTeEq6Ky9dWh1jDxtreW2SP/SfJAXRaDEkEMJCM7iAg
         ZscrJkvX21xIFQdqoYm85h7minU5wBZ3lpEF+kfsToeav7ofwL/KNEV2V3E/CVdhZ8/u
         xj1PYIQ1xyxSDnmaulvHFHQqSHkSwsQXwjflzlI/MfepKnVVTY8ahE7cKTi8YrS+tGA6
         EbBferObQ0883EcQRp2s268ECqoXSSX62++5xM/sJwDKWuZt4mmgThEmTW0jSlvlBqny
         d4kkAkjO0JgebUd6CMMlJprTr5D2CnPWXkMNB7Gr5QZXNNbqteIce4ax1yeA8HeKe8yr
         6WfQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=kSMhOl8o3b+0/7blJ2pgDmD49kKbnnRR31GUTqoWKgM=;
        fh=IV4K8+BHWm4mPdRklf1A4IWSFEDAhNAYi7ght1tQN+0=;
        b=RVt3PeXkoPtGxUwJ1u0ozY4dpMuhJtEF9KEVT1GVpAePKYwobAsdUWxo6BpomrVYSY
         LulxhmawyF+hSPPuAFuMIGVmFbPzXFp4p7SgQerMGdvTaDbRtwOEd8bFLQwI3K1KQ0xh
         ObOheLzbQYIuvMCaWmV5VTzEWBAym7DgpK1C99eFKpJ+4QxnJF1cXcuG8w5ERt7+e/dw
         e2SZZ18J+fNBVGRig5Mbks1MLDgKsYAAXfYYYKm79Z2HGllhKUXJ9GThHOnosQaPj11I
         08ITDvkJ17occlxLtzT1/1vx44N4RmlBDSHC1P09zQv27/RZ0dWxs5MK5t744LZZ3P/L
         sEDw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=3Z9EkjHz;
       spf=pass (google.com: domain of glider@google.com designates 2001:4860:4864:20::32 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1743606094; x=1744210894; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=kSMhOl8o3b+0/7blJ2pgDmD49kKbnnRR31GUTqoWKgM=;
        b=e8ILvh8VUW93um9i9JwwWfH0+b6MH6vXKVwD5eGTk7cJuQIzVePRHCp6ePLFCprrMI
         D06/0qfdC14x0XF5Txixzdy40R6cqovraxHwC1fNZbMlzLkbZ7eFT/VHA12FNsoRcB+4
         aLF4u0BMq17xGK6diYdQxIOQ1Qsqe9kQSh2FZ3Jq8DJkkmMuIEU0Ohy3ZPfUDH6sIGrX
         fD+zAiT9uA4bRXNxhbQI27nbQmzP3qDgs9UrGUqN6CXw271hwBbpB9B7VvT4wCoKLj+L
         XkUYrfnhPIrPB2bE8IGS4Ljdx+GNnOq8iaiMqeKM36zpLBsrmbjmncnXXVpDmzH/Aiaa
         VTFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1743606094; x=1744210894;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=kSMhOl8o3b+0/7blJ2pgDmD49kKbnnRR31GUTqoWKgM=;
        b=izW7O6u1GPuFmToQ989+S4LtzGhbt4kQEbNSqXENbchvWd/z9G44CIDIR0TKo+OyEo
         shYawPVkvnNQk8tw9/V8G6b++Gso9NhSo0G8QDHhtkdPkxtiCEJglS5YiVwhVQQ77Vqv
         67hUtjq62iWV2xU8F7OpTtl0RZgI4KFd548A/uW+fGA37lbhdwIic+Es8TQfHMCi+E1B
         ZCzoqyWJaE850toU3CIOh+muMTxuk1ebFyNNKLA7TDR9/QxjdQqMC+Y8REXZm31mmrWi
         kBqb2SuJVhOGTVQKyaKqAWymmp3t/Z2nrJqG2g7CgebstMbA1VD+vAl0IsHg/manYOMq
         z/mg==
X-Forwarded-Encrypted: i=2; AJvYcCVEhS2YgKZ/JfNSeDhbl8FO2LZwwZ++MvuqtXZV+W1XXtlmsmlSSJG+d6uj0t1jM4EXSXmFkA==@lfdr.de
X-Gm-Message-State: AOJu0YwdWRZqrqO22yz//WKrnYtLYtewv3pc9tFq9n5vxpBZG1cSEsNN
	gAleneG2D6Jkx75PX7PnUUWfrj7jV3z0xd7XAB8IlMBSH2JUqfU9
X-Google-Smtp-Source: AGHT+IFzNyOhwrFDutqo1qzOaLDq9BFKI79YMKWh4R88aSa1JijuYNOylbbhcUWWIyP7iGzr9bNi5g==
X-Received: by 2002:a17:902:cec3:b0:223:2630:6b82 with SMTP id d9443c01a7336-2295be30cd6mr113231685ad.10.1743606093949;
        Wed, 02 Apr 2025 08:01:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAJ+wDcruK15qEV39xVprbbSbgZ8f2F9OJtdBwfhCQEyWQ==
Received: by 2002:a17:902:d588:b0:21f:7c14:e7f5 with SMTP id
 d9443c01a7336-229762092b6ls44085ad.0.-pod-prod-01-us; Wed, 02 Apr 2025
 08:01:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUbl53PzxMYjFfk6UXWFpspu7XAdCmOoVZlUkzQsNTpexfusZJSLZxND/7SeJ0shzr6xOxidRw0MH4=@googlegroups.com
X-Received: by 2002:a17:902:ea07:b0:221:7b4a:476c with SMTP id d9443c01a7336-2295be82fb9mr85216855ad.18.1743606092151;
        Wed, 02 Apr 2025 08:01:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1743606092; cv=none;
        d=google.com; s=arc-20240605;
        b=TI3zENFS+toPX2baCuTKZq+NOYSx8x4L2qTBWw+Ax4g23vjFPVt4s70gi4sxK+GOU8
         EwRUHZXTbvaREVfBZ8uDTZyfgOGJzDiNHWsQ5TdV5LEolhtOQqH1O07NQT9BiZdrQgv+
         QHfrRiY9JH1G9oiUTLd8U3J/sVKl5En3qQtM9YxH+n2e0xmmrCaAJSf2t/jRvI/BZ+sL
         PLskHeEIGthVIc4BuPDzljOoqmXJoEd++yg9MgNBGv7a2I63eCcY/+6VXADvp46H8NFo
         9A6TiDwximFVQQBgl4YA5rrPHLxbe5521YQxoB/VJBf8oxztAEIBcJMeqH9bpB4t2BS5
         DRfA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=a1HjAqT63g+EpaN+I+GXlejKpW2Kw7rHLLAbGdjQ+L8=;
        fh=pS//LXnfXrGOFYCWlee5aj1cpi1StzxLYo1vD6rc48Q=;
        b=N9/8ueUiZo4Shy3EnFrwbKOXcBMHuVCEPs4/aqtV/amzWzfB2ALA3GjIfhJQGZxUtL
         9sj91wlEmO6sdDVw10thGcWqwkwfTttGvO2kNZaNFvnaAoIgZjXpNicA/ZvlKTEcJ4FA
         gSoEz52eZfhJAFrqkfMU97CSas9dAT8zc6UdFI4GNRgoZ8tYBowCJMafUgsLlcZoGaB5
         UTApTCrYDd4g5bID06It+JoK1/hC+HfMJ+M5NtxTlOcW5Zuo0PX8ELm/MSdHomsF8bMD
         UzDCZ+lp1zZh3mkUJzrG9tW4I1fTBPpNeKiIY3pO3tmyBRDMnxvTGTGNeCxuyHAQ6N1N
         hVRw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=3Z9EkjHz;
       spf=pass (google.com: domain of glider@google.com designates 2001:4860:4864:20::32 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-oa1-x32.google.com (mail-oa1-x32.google.com. [2001:4860:4864:20::32])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-739710d96cdsi599002b3a.6.2025.04.02.08.01.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 02 Apr 2025 08:01:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2001:4860:4864:20::32 as permitted sender) client-ip=2001:4860:4864:20::32;
Received: by mail-oa1-x32.google.com with SMTP id 586e51a60fabf-2cc57330163so710112fac.2
        for <kasan-dev@googlegroups.com>; Wed, 02 Apr 2025 08:01:32 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXhJdbdxOp+wfPQsmsk3ULDYndr5s1dU1RPH6zAEzzWSkib8KZAAp7kgKO0Sac8hTrGiYCI/1eu2z4=@googlegroups.com
X-Gm-Gg: ASbGncvbMzVW6BT9LaFjcgMG5lrl85kACB6jr+OAERvcAu6Dy2QSAUXXHH6IdC5vcmA
	puvNY42rPFSvJJdvVNcpB8HT7f1Y/C9PgfvzbYGyUIDN0o3Nkd/wGnKKvLARGqkAp+mAD/dM4mb
	2mbTq3luU5JWtCUfeCvnqIeovC62JjV0jVvzPgsl7UbTw/N7txytkiFyuI
X-Received: by 2002:a05:6870:648a:b0:29e:70c7:a3f7 with SMTP id
 586e51a60fabf-2cc37f37c4bmr4368642fac.4.1743606091166; Wed, 02 Apr 2025
 08:01:31 -0700 (PDT)
MIME-Version: 1.0
References: <20250321145332.3481843-1-kent.overstreet@linux.dev>
In-Reply-To: <20250321145332.3481843-1-kent.overstreet@linux.dev>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 2 Apr 2025 17:00:54 +0200
X-Gm-Features: AQ5f1JpNqfU3rM2NuGQ3cqbzOd9B0Hx6vNdgsVkT12yuqXCWvnfIcOjW5lDaANE
Message-ID: <CAG_fn=WmyMug7mkD57OubPz31mH_W7C1u-VStCQ7UeYh_CCtPg@mail.gmail.com>
Subject: Re: [PATCH] kmsan: disable recursion in kmsan_handle_dma()
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=3Z9EkjHz;       spf=pass
 (google.com: domain of glider@google.com designates 2001:4860:4864:20::32 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Fri, Mar 21, 2025 at 3:53=E2=80=AFPM Kent Overstreet
<kent.overstreet@linux.dev> wrote:
>
> I'm not sure if this check was left out for some reason, maybe have a
> look? But it does fix kmsan when run from ktest:
>
> https://evilpiepirate.org/git/ktest.git/

Kent, do you happen to have a recursion stack trace for this problem?
Or maybe you can share the repro steps?

I started looking, and in general I don't like how inconsistently
kmsan_in_runtime() is checked in hooks.c
I am currently trying to apply Marco's capability analysis
(https://web.git.kernel.org/pub/scm/linux/kernel/git/melver/linux.git/log/?=
h=3Dcap-analysis/dev)
to validate these checks.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DWmyMug7mkD57OubPz31mH_W7C1u-VStCQ7UeYh_CCtPg%40mail.gmail.com.
