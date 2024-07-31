Return-Path: <kasan-dev+bncBCAJFDXE4QGBBMUPU22QMGQEFYCLDCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id DA6C79423E2
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Jul 2024 02:39:15 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-52efa034543sf6505972e87.3
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Jul 2024 17:39:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722386355; cv=pass;
        d=google.com; s=arc-20160816;
        b=r+tECVPJVhsTBwYkrmXxml0uf03eeIjn0ZvGNji8ZNp7ELaiTFGFZKe63H2QTRLfKf
         jXJ/vczVumtDo1qSHqtbauQUgdU1HF9ijkqaoifqv8Rlhnx2zRBnuWlTjgJKQ0MwPYKX
         RxvflHC/Hz8Dj7Sdu5PdbL+1V80SnlnVxeSVi+r858Jp4PSlOvXFyxXWoaug68w7ld2q
         JbYym78U4HeosZSLRgOhQQ7tTifmgZEF2btTS+2o7EH0Q/ZoCmn8J0Tzkw8n38/+UOjB
         TBaeU1EK418Tz/HbMHiJ0te0FFXrZkkCCF5Z9wkNvCVfzDbBxZJOL4wajk8xe0ZrgBVN
         7EkA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=Z2Uc0OOebCwIO0DaRbN8eVehT7j5WIGalmmxQF30WR8=;
        fh=EbQriLqGQxpRqdkYp5/OiKOUx3030AgO5ChQn4o9hs8=;
        b=x8WPE9FisTnMM+afPfOD6zKzfMkDcmba54GCZfRqKc3uWVVTimJj9QzBMVoKYUe7vk
         sOKN/TnvU262zGEfJYz0Sz5Lkv9GQKHcfRqkSgFonrWbC5v/2yqiYwXfJ5z7rec2Adcc
         aG2InGKd2C/M69UAkvX4FHF6foOiBcWyKGycZCbYZtwP473xi3dOnUKOM/dMOJnJTmjS
         9eDywc2F5X15k4ewEYRXOrVLUESAvyW+nONhNW0buJ3037BJDr6R3Qgr6iu0+AV3FMxY
         FpDqwUexSHBPAcbjOvLO+ABb6HVRoMV/R+cIBfW/3pdeBki/gdKaN0+SB+idY8Q1QhlF
         dcnw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=RC2afwdh;
       spf=pass (google.com: domain of adrianhuang0701@gmail.com designates 2a00:1450:4864:20::22b as permitted sender) smtp.mailfrom=adrianhuang0701@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722386355; x=1722991155; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Z2Uc0OOebCwIO0DaRbN8eVehT7j5WIGalmmxQF30WR8=;
        b=Y24zLTwHYozvLU1wTtky4wpe7KS4RtyEikAwiZbmZ0kEL0X6L6NR9JOR2IjFzH/ojz
         Tzse8UOSDJd9bQivL4t6DuxVEX7HkyOaHArIYzI/V6UCLiRB+R8M8nsFYtlm9LzNGLnE
         V/Hr32Zf6ZZabB+QyJbFgGtWnYZ/t13eLN/A3yE/P3enyLnoM7CXYczHHcH6VKTJZrD2
         rcLgf3C8ydvCTdS0hAMkYQ46FOGsbhNUzMUADEU6nd9ot0KeQn9wpEMtPFqwVT4p15Ny
         APHII05zDpzikMpI+AJFTInx7geXEPmR5sJBrOJrSvKso84xscI6TrvnGVIyR+kL3AeI
         PlHw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1722386355; x=1722991155; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Z2Uc0OOebCwIO0DaRbN8eVehT7j5WIGalmmxQF30WR8=;
        b=GtHVQBpu10BTK2rSP1nG43bIQFK3q16BGLlo0pEEPLunMNuFrlaIU8eNMoxotbvUSc
         /bpnXRBDpXOOU1dcDnlxooyWIKs8EBPY4NiS+0WEckCwJO2haPJjjZ15rAk8f1kjXuxP
         fq9TmKWQAE1tlP6kmroyiiOTTGTFHfzoOJs1yv+xXYsnwuDFzRO99AJ9zl4SKmfmSSss
         xYW1yL3qKheFVAARiMTGnMj6IfeFJtKfc9uJ/ujDRdRQzvmeeRcCKwLTFeaGe92A9jZr
         zzx7w4nBCGJNGuvEQ2QHC9Qg3S8M4rXqUW4+K0j8SzUeuBRUsinrjpNI1Md/wbqmknfn
         SfAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722386355; x=1722991155;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Z2Uc0OOebCwIO0DaRbN8eVehT7j5WIGalmmxQF30WR8=;
        b=lVezBD9KUSCPySmo/H2dLIQbjPRt0N9DVJnAV5S8rghpCPZXx7ODgzkI5OrxhB9qoI
         2InvpVmQT7+4thuDMX6AYQoNnnoqdy029Isms9AvoknKqXLvD8SRTvp9Uh3kvayHjluE
         Y5eSs1Wfd0Gn2PVwts34Ibk2qYJxE9HeaCyDZUYDecDQpc/Yz+fD06ICw/XgGNag4pKT
         1h9LyVghptYyfknsyI2U61CoZ3IHJw6UxkOSYaJC4pQ4v6eUsM6eDXNeL3bQFRtixYRR
         N7CTa4rxT1c54j10rCXaCA31oyy/fmMdDIPGJ7MjLX4rdE4k7jci5/JSG30l914uA6ph
         TLEg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUO6A4L6RE2XQUd9Rn9BF2jfkOUZxu/hM2Mh9/7stbVgWFz1YkfXdFJYH6BxIYuM3REcrRNEWR73dOxbqYHYy/0a+sQV/yhKg==
X-Gm-Message-State: AOJu0YzUxQRxZQI7JtTrOy1vNYd24/7qZEDUuW8svFjChVwmg4i/n/Ma
	4tnkorTPNhwlJ26qKVEsceU9ZEOUMutE5zofuP2gkuRMsxZNWdGU
X-Google-Smtp-Source: AGHT+IEz4bg9KV7exZepd+PYbfxRdhZX86Bt0luz40nAqra+CkcDwLNj4RDOwI7yqY77Ef3PKniM6w==
X-Received: by 2002:ac2:43d9:0:b0:52e:9d28:c28a with SMTP id 2adb3069b0e04-5309b27d489mr7358919e87.26.1722386354661;
        Tue, 30 Jul 2024 17:39:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4e03:0:b0:52e:9d2f:234 with SMTP id 2adb3069b0e04-52fd3f5456als221168e87.0.-pod-prod-06-eu;
 Tue, 30 Jul 2024 17:39:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU8XQNIr+gS1v1rV3BpV/N/ILzVzGEJroP8h+8YxB0FkhIeVowt33hc7Or7iMdkNYptn6hzTFRx/7Q1LZ4oRWuSKJjH7jvxCf8zhg==
X-Received: by 2002:ac2:54b7:0:b0:52c:db06:ee60 with SMTP id 2adb3069b0e04-5309b2bb677mr7974689e87.41.1722386352727;
        Tue, 30 Jul 2024 17:39:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722386352; cv=none;
        d=google.com; s=arc-20160816;
        b=rziymEVSLKOTwhqN/hXHhCSZCzIposl0ds1httSuANd2LyYmSJHNZnUxqzrCKZNG72
         Db4d4AuBcvw5sZkBLxlXieAt4RNPKxowFaDMbKBomcyhTWwDvH1wZsaPn8tweHlzV7su
         9jg1ZKEIRSpciRHgLyP7lOroKBDLKtxdeSFEIaNZ68nmeWWxGcmBWcuSKozrBg7EsdzX
         Flk/lUzrTr2bSf1uKSEAE088lysEfPsW1z+vkDLfj+zpDApzqIuoKPYja1Ukru9STPS5
         HsA84axRNBGNg8kjbSWPGyLFcK2g1bPzHhw4hNpl5ZzW76OfuTvh0nQd7646qV6pVNhK
         U4HA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=G78J1xazOqAfpXn0/qpj2FC1yrY6QemILkcM54iNNJQ=;
        fh=r07jO2al8Ihu+FeRZuoWw8LK//PZPwW7dNWLZa2AchA=;
        b=B+umiXLw8iqjhmhUyfRm8PaMIO6TkFywA77tzjrGk7Oofy3qVVKDsXO1PAsD5z9pqt
         liFo9OeVTeZB989apbJ4j+sVpANVS4kBLVX2ZO9+yTr0NI3jRXUUVdMUJtqJWcyI9ACP
         L7sDhgu1XNiI7jh0Ue3+FB6i7jxnzfTl0vVKq4p205WAXwUUQVyJq07PksIGl2aBtIpq
         CCv7IJ/omdT2fhhVyaNQESdNrYDf26xt1fyBDbHKjIT3O4kc5IlGO+j5tBMKfoms7Xbh
         QMT+DGJfC90CaXClukZlUni0mJRD6RL0jGf8I9AbkN+o42tvZZQPqcpX9MKNc3kWxHRc
         UoEQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=RC2afwdh;
       spf=pass (google.com: domain of adrianhuang0701@gmail.com designates 2a00:1450:4864:20::22b as permitted sender) smtp.mailfrom=adrianhuang0701@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x22b.google.com (mail-lj1-x22b.google.com. [2a00:1450:4864:20::22b])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-52fd5bde8ebsi285844e87.11.2024.07.30.17.39.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Jul 2024 17:39:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of adrianhuang0701@gmail.com designates 2a00:1450:4864:20::22b as permitted sender) client-ip=2a00:1450:4864:20::22b;
Received: by mail-lj1-x22b.google.com with SMTP id 38308e7fff4ca-2ee920b0781so57470671fa.1
        for <kasan-dev@googlegroups.com>; Tue, 30 Jul 2024 17:39:12 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVCtwnFwUQ8IcmhR59CgphZ+3UpuDUvymz+7B2NzWWbFGeCo76YsMBhW44MUo6H06COxuOxKO63/ZRHlt0BkmKZPregchGkaJxUDg==
X-Received: by 2002:a2e:b711:0:b0:2ef:2e6b:4102 with SMTP id
 38308e7fff4ca-2f12ee626aemr82767921fa.43.1722386351769; Tue, 30 Jul 2024
 17:39:11 -0700 (PDT)
MIME-Version: 1.0
References: <Zqd9AsI5tWH7AukU@pc636> <20240730093630.5603-1-ahuang12@lenovo.com>
 <ZqjQp8NrTYM_ORN1@pc636> <CAHKZfL3c2Y91yP6X5+GUDCsN6QAa9L46czzJh+iQ6LhGJcAeqw@mail.gmail.com>
 <ZqkX3mYBPuUf0Gi5@pc636>
In-Reply-To: <ZqkX3mYBPuUf0Gi5@pc636>
From: Huang Adrian <adrianhuang0701@gmail.com>
Date: Wed, 31 Jul 2024 08:39:00 +0800
Message-ID: <CAHKZfL1i3D7wgbdLWz3xiK7KkAXAxrsyQjFmFarrM94tJPYh3Q@mail.gmail.com>
Subject: Re: [PATCH 1/1] mm/vmalloc: Combine all TLB flush operations of KASAN
 shadow virtual address into one operation
To: Uladzislau Rezki <urezki@gmail.com>
Cc: ahuang12@lenovo.com, akpm@linux-foundation.org, andreyknvl@gmail.com, 
	bhe@redhat.com, dvyukov@google.com, glider@google.com, hch@infradead.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	ryabinin.a.a@gmail.com, sunjw10@lenovo.com, vincenzo.frascino@arm.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: AdrianHuang0701@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=RC2afwdh;       spf=pass
 (google.com: domain of adrianhuang0701@gmail.com designates
 2a00:1450:4864:20::22b as permitted sender) smtp.mailfrom=adrianhuang0701@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

On Wed, Jul 31, 2024 at 12:42=E2=80=AFAM Uladzislau Rezki <urezki@gmail.com=
> wrote:
> Thank you for posting this! So tasklist_lock is not a problem.
> I assume you have a full output of lock_stat. Could you please
> paste it for v6.11-rc1 + KASAN?

Full output: https://gist.github.com/AdrianHuang/2c2c97f533ba467ff327815902=
79ccc9

-- Adrian

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAHKZfL1i3D7wgbdLWz3xiK7KkAXAxrsyQjFmFarrM94tJPYh3Q%40mail.gmail.=
com.
