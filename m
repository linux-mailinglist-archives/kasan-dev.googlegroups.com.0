Return-Path: <kasan-dev+bncBCY5ZKN6ZAFRBZO64K6QMGQEKSZHLKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2C3A0A3FC24
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Feb 2025 17:52:55 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-30925cb0253sf11764351fa.3
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Feb 2025 08:52:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740156774; cv=pass;
        d=google.com; s=arc-20240605;
        b=jDNBtDaOyjm1r23gTT7qcrM1c4Vzulix5EO+ncpbpxZZ1ITrdVj4fenX9lbIs7wcl0
         K8UifNXDtRssoS4Rj5tIytZP476xdmqucsgWK23SpRjxQj1KCKPp7DLeJvRN/jVRc3/h
         Tgj9z0Xz9Zew9yQdP0tJRBPcP+xcFL3r1ePuCP17/JX8J/pJzhkzjXsgHVsK1qx8QdLf
         D8y0NUQw0xo4jbiUHyIJjKUuME01wFMXWLyXzfTvJgtPndJnxJdPnmeHHl0m6wCluhJH
         QXBrID+ETg8BhoeXI0tbFg1CV4yGoU1Zm0bNlnvQz8Zm5Xjvw/wNAlRa/qsejMBbRlZu
         6q8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=yN/n6xczXQing/CePgRhcMFllMK2ooxedNONZOi4tzc=;
        fh=Lusi6eBpeoy9ObT01EydKgA8VrQXTPJzUKdC6WuVrm0=;
        b=MJV1xWJBnbQk7L1pZVl5cXKb9QLISytMW6lKSKz4WP4/YxvhCzEiETSQbaU5ZJ9cdK
         GDHEqEGUQ4bcdz15syUN77WPK3keF/DgwR66pFaSMaevo6JT5eLxNdTT9N8rwo/BVAJd
         ZRgl5IURhskAiyeCY7/dyLNP+RQAD3zj73UubWGH9l0gi8DkVsS8uQ/JdtQB5aW/vIQa
         fB4nUnD5IgEaQHI9Ds5B2VF0BUUW7wEjqAMEqQn3HS6gHg+JDQrL9PaeY1+px6smmzVz
         lN8vyvaFcJTPTDewfo344Hj8ha6i06hyx6fCCH0Jyjv1yRJ/Bq64K/Euw1XMYD5xBHwI
         dkEg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=fzjequgu;
       spf=pass (google.com: domain of mjguzik@gmail.com designates 2a00:1450:4864:20::632 as permitted sender) smtp.mailfrom=mjguzik@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740156774; x=1740761574; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=yN/n6xczXQing/CePgRhcMFllMK2ooxedNONZOi4tzc=;
        b=QJs6Sqf/X1X3Y8oZG54MnT7jMnRJEPsRnZujGk0xFWRQK4IyKyAfhuier4UWNeIw7C
         EDMpKN59wvRBt4jyVcv5b7xRv49XWx/5lUNlBLdnGY/gNAvYjFbvo63SSa9NjxuOb4Ig
         DCM2n2EsqmLRob25bjwLs3Q77e9IhVNnhnD579jQeIYk+OK9VRNrKh83KQaVFagAiGfx
         9QM8qZ7oOTohKXfDvL+0ej2hNScSnJzk6oLNlfnJpwGGeIV0DbsxrA5WJ8gQ8b6QbIR3
         JhJqeKgVR56uxgguv6O/M3XnXe1YHSrIDS1FlMGbG81iaUtnMoxh3yTyPj7WwEIGxUt0
         kQjw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1740156774; x=1740761574; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=yN/n6xczXQing/CePgRhcMFllMK2ooxedNONZOi4tzc=;
        b=Qc/DPGy7yR2+LBN/iyWjEGSgfF91IBg9Sla1AWyBqECHW7YqODF93x2sI3YfgRbuyN
         b/hCIE1UVXQq8obw0eRQVPJZyC2NXMdX38iKeq4/2pDOb5sOHXs0I2lVP5kECmgzdd3s
         pfHdljEhU1MYCzoj6nvGGbDdlmN7+L8/1mdNb2qFOvghsQz25HkRuLdmxKhhF0s5JE8A
         DFOU4gZJo65CQ6S5wpixhuGFmtP6ZmKVez55X86RcqrZ0EWmB8+S/51d0FxeyDNvoLHc
         5Vcqj929S8JmsQXErjYk/8tPTtiZxhG0rYQyy0Xx8R28ryp39tcV7ti0DlUqKYCr0FO6
         oh/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740156774; x=1740761574;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=yN/n6xczXQing/CePgRhcMFllMK2ooxedNONZOi4tzc=;
        b=kzB4SNixYn/j7oksX2gPR5adCbrxYqWen/RN4EzPt3Q2Eji3yDye85WaEVNVEaJWp8
         n8Dj0kFHFjT45T9y+SBiiB1Yew3i894ZxiW07vYxc6ZXUF3joBl/zcZkpu1Du5xoP28z
         lTky41B1hXIBP22EJI/OiiU8xLK4a8HF0Z2QVCHZhv4sR847hg8lRNklALrl+VTxcSud
         ZjCKeuUB1g3Q/co3lmkvmXkGALFuS1KNmhvQyxrA5PpJKKA8JColXotexF4ZQzWIRumd
         sZ1OIJgRAnZSlI7r7uaz/J9fngLJZ6rPHgpnFGFCFpfyepjaLCFJ4ksySvCuyJ/RdGKt
         U4uQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUNNu+VgZFs+SLnsc6ggxTEHslgfg+fVLUGbqOEaWJP11IPC6o5Y7S7rJFEmhVeT6Cx440G2w==@lfdr.de
X-Gm-Message-State: AOJu0YyFtV/2TdN7Cyb1i/8vBqeu7F9nU1tr5EfUL3nrXB+AAjdwLudw
	fB2KELCPDhNBPoNY4DH8d4QZa0G4eJEQGq9wgV3YfJC+VAAHqv3T
X-Google-Smtp-Source: AGHT+IFg9wieql53PTzCvLrLMqkOugyPe23kSF7cNqoXM/wYhKs5bjvNcCkCDI82iS3Jk/iElD56yg==
X-Received: by 2002:a2e:9595:0:b0:30a:440e:fe67 with SMTP id 38308e7fff4ca-30a599a2c51mr13103961fa.35.1740156773550;
        Fri, 21 Feb 2025 08:52:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVH1jiTAs0vZBe8DV02U0+M3IVKX75yLGMh/GAwxu0cLgg==
Received: by 2002:a05:651c:1545:b0:30a:35dd:ee0 with SMTP id
 38308e7fff4ca-30a521d3642ls539251fa.1.-pod-prod-01-eu; Fri, 21 Feb 2025
 08:52:51 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUVwLNyCwfQcKoTKzJABRq/o1UA9HyWTeEAMkMjmfri2eV0KXxyU6LmU58adDdiCYtXrQimGBmuESk=@googlegroups.com
X-Received: by 2002:a2e:83d0:0:b0:309:2627:8adc with SMTP id 38308e7fff4ca-30a5985d8ebmr11819441fa.8.1740156771052;
        Fri, 21 Feb 2025 08:52:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740156771; cv=none;
        d=google.com; s=arc-20240605;
        b=ClMgbC3N9d39mF5G/wOtrRO0knLdhaNqVYKxok04KmaCIWUmfzgPOuKuI3QVYmYppU
         cEGdvi9ht0Id0IHI2fBoI2nu4n83Cpdyt680URlxwRxvB4/80Du75Bpvr+mBw7qbSNJT
         362ik6bK0uAnQTWXxWNIHguC/jgD/TfdHOWyl81FHgqHb/5eAklnTc+ykL9VTZYVaSl+
         J5OP2het7NLRxLfA4DE2F4Lc2OgOHI+SzIcJvMYx1rKQKpIFC5v2mUiL8yHEkB3icbgI
         G0ebzK1sOsY1Ka34JptyHTJGtoPlSK+avoLdQ8knTMsImWsuC6xQzag9sV5IrkFKpQtA
         9MWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=vO8sI//TeIWtExyYtaD4Exo5QVqQp3kkPzLWvb0G4ZQ=;
        fh=3SiwMzeq4BbN+yVXCWwoDZyge8hN3IJ9qhAs9hBEynQ=;
        b=e0PScb1JGoZbs4czQHz7dMm7tvHtmNzaSOrU7wiWzfpzhTxyb2n4GBStdzqBMQpVVj
         0TX78U8KItViN6KmMdcGEa9o90M7b728U5wLldkiFqz7yAecPOHVituraaJZPL0a8NmN
         95W1qcrFyhA2DphmqaITYAUcyYh0lI23N1/EO1MBvmrpaUQOlXJMj6Cmpx4ViDYGF0OQ
         /z44SGbLQIeynVXnd2I+1D3Z4s7+qdjNezdLGjHj33xQraUSMit1IILlGZyK/amNdxJf
         ALwQgxJOso2xQl4L7B7jrHAD11pEb7KaZ21/kZuqR0xMtqICZ9rkhmpIkR/5KtUIc4Dr
         cN9A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=fzjequgu;
       spf=pass (google.com: domain of mjguzik@gmail.com designates 2a00:1450:4864:20::632 as permitted sender) smtp.mailfrom=mjguzik@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x632.google.com (mail-ej1-x632.google.com. [2a00:1450:4864:20::632])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-3091d72aa20si3148021fa.1.2025.02.21.08.52.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 21 Feb 2025 08:52:51 -0800 (PST)
Received-SPF: pass (google.com: domain of mjguzik@gmail.com designates 2a00:1450:4864:20::632 as permitted sender) client-ip=2a00:1450:4864:20::632;
Received: by mail-ej1-x632.google.com with SMTP id a640c23a62f3a-abb79af88afso431320866b.1
        for <kasan-dev@googlegroups.com>; Fri, 21 Feb 2025 08:52:51 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXW/j7mZiijYxim9itnK4MlBYvPbTSmUiuPcefVaU74sI68F2Xks/o7ZFom6lmRri8jbT8EaiBShvQ=@googlegroups.com
X-Gm-Gg: ASbGnctIGWhiHyoTstfI/rGwE78Kn6tdM5bFn8xbq6hRTAIZr6b0N8EDcxlZnWVt5g1
	55xPGXevPTnLHXnuGOQBPNg14jmmTLBiAIlZQcjOHaG9NjCx/HgxJsz3+DhAzGoBrJuJVxooiwq
	YWpufavA==
X-Received: by 2002:a17:907:944b:b0:abb:c647:a4c1 with SMTP id
 a640c23a62f3a-abc09e37de2mr406314466b.52.1740156770066; Fri, 21 Feb 2025
 08:52:50 -0800 (PST)
MIME-Version: 1.0
References: <20240807-b4-slab-kfree_rcu-destroy-v2-0-ea79102f428c@suse.cz>
 <20240807-b4-slab-kfree_rcu-destroy-v2-6-ea79102f428c@suse.cz>
 <Z7iqJtCjHKfo8Kho@kbusch-mbp> <CAGudoHGF8ULGPEE5E6ZCTcVnm3qjY0BfT2DmBjKohW_rDK0JSw@mail.gmail.com>
In-Reply-To: <CAGudoHGF8ULGPEE5E6ZCTcVnm3qjY0BfT2DmBjKohW_rDK0JSw@mail.gmail.com>
From: Mateusz Guzik <mjguzik@gmail.com>
Date: Fri, 21 Feb 2025 17:52:38 +0100
X-Gm-Features: AWEUYZldjsBOz6dW6Mngy0JPyOmqYkSKLBXfGnQS2tXN2Unv8ZD0Hi38e_Hg0os
Message-ID: <CAGudoHHeLDgSt2Lt7AO1qpN7uf-SOJ=LP9y+UG4zv0EY8gA2Jw@mail.gmail.com>
Subject: Re: [PATCH v2 6/7] mm, slab: call kvfree_rcu_barrier() from kmem_cache_destroy()
To: Keith Busch <kbusch@kernel.org>
Cc: Vlastimil Babka <vbabka@suse.cz>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Joel Fernandes <joel@joelfernandes.org>, Josh Triplett <josh@joshtriplett.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Lai Jiangshan <jiangshanlai@gmail.com>, 
	Zqiang <qiang.zhang1211@gmail.com>, Julia Lawall <Julia.Lawall@inria.fr>, 
	Jakub Kicinski <kuba@kernel.org>, "Jason A. Donenfeld" <Jason@zx2c4.com>, 
	"Uladzislau Rezki (Sony)" <urezki@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, rcu@vger.kernel.org, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com, Jann Horn <jannh@google.com>, 
	linux-nvme@lists.infradead.org, leitao@debian.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: mjguzik@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=fzjequgu;       spf=pass
 (google.com: domain of mjguzik@gmail.com designates 2a00:1450:4864:20::632 as
 permitted sender) smtp.mailfrom=mjguzik@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Fri, Feb 21, 2025 at 5:51=E2=80=AFPM Mateusz Guzik <mjguzik@gmail.com> w=
rote:
>
> On Fri, Feb 21, 2025 at 5:30=E2=80=AFPM Keith Busch <kbusch@kernel.org> w=
rote:
> > This patch appears to be triggering a new warning in certain conditions
> > when tearing down an nvme namespace's block device. Stack trace is at
> > the end.
> >
> > The warning indicates that this shouldn't be called from a
> > WQ_MEM_RECLAIM workqueue. This workqueue is responsible for bringing up
> > and tearing down block devices, so this is a memory reclaim use AIUI.
> > I'm a bit confused why we can't tear down a disk from within a memory
> > reclaim workqueue. Is the recommended solution to simply remove the WQ
> > flag when creating the workqueue?
> >
>
> This ends up calling into bioset_exit -> bio_put_slab -> kmem_cache_destr=
oy
>
> Sizes of the bio- slabs are off the beaten path, so it may be they
> make sense to exist.
>
> With the assumption that caches should be there, this can instead
> invoke kmem_cache_destroy from a queue where it is safe to do it. This
> is not supposed to be a frequent operation.

Erm, I mean defer the operation to a queue which can safely do it.

--=20
Mateusz Guzik <mjguzik gmail.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AGudoHHeLDgSt2Lt7AO1qpN7uf-SOJ%3DLP9y%2BUG4zv0EY8gA2Jw%40mail.gmail.com.
