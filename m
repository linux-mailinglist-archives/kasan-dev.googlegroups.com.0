Return-Path: <kasan-dev+bncBCCMH5WKTMGRB56H26VAMGQELW7WAAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 6A0247EDDCA
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Nov 2023 10:42:17 +0100 (CET)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-1cc2a0c7c6csf7427645ad.1
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Nov 2023 01:42:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700127736; cv=pass;
        d=google.com; s=arc-20160816;
        b=YGRMI8ZpEVk13BFGtjmg7crvnEJbPObIbPE8XbSR90/VMsJMnMIFZOhPP8mzdYJt2U
         9FsZAwwcbuh/pGdhKXyso6UmDVT27yt/2VQRWYXomHsZ3vC/6LcbNGWhP24QZcG0BwmA
         k08l+MbhkO4nwCTCUARWmQ4X0Mnajd+974hseN8A/akKLxITGYxRTPA987+cHAxRaXnJ
         N2gFbpI3oNQAxndf4aunHCdNfnLKgUOxxEy8x2jcYrr9Jd309ucccJm9GHPoMG3v5Rj8
         9L+e1Fuxb3FIIJC9UFuZiBcW8hZNrGKDQ7ScruOjsxPnR5WeQ0/7ft2RJjir/b6r01pL
         aJig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=zgTAA/fXkhuI+SjSIxB1KcceCAukG3MIFyZlQp6TERI=;
        fh=YZa8vkdUz4pzRj6QFVU/SyYW+LsIH/Wz0o5e5dUhKFo=;
        b=PSzNwwcW7JfVBizzaAKdFHNkO/dBSChSKOcM9+r3OaHnG8TeX89ywsVv3eKX1y/61a
         8awfL/LZLlLSamWkeQ1q8b57GWtYaKvVNy7teksM5+fE+8Y3QG4Ut8ww15egudNZOL75
         rnjHKxK/QO3DE+IFVUxvumH4ATMU7Z8Ez96bbSCOh6jz9Ncj/TCX0Nua+593lGQ4mKsN
         cNdkv7Ef116023tcQzg3MfZXeTbMfV0z2wnQKOHhYQsDlThM7sMkQLiVE1K9S8JZN9qK
         btuWI+1bmGEDHttgbqgCj8AcX1UAUx02H3NS3j+mj/cMDjuUKXElT1xpCdti6IciT+ZU
         uFuA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=S2U4U74q;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700127736; x=1700732536; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=zgTAA/fXkhuI+SjSIxB1KcceCAukG3MIFyZlQp6TERI=;
        b=YtB+sMtxWIVNCXdoeUO1thg1Cd4XWgk5DUUkuvXNiYsE18P3KRuuJe/7CqNAQBhVQo
         qwHzgaekh1v5ijnYsgnRXwrlNuISmhnrJz0QBjTRFQEDk88S8EzgG7ZmwSDodVqeY42d
         7i1xhnAkybNy9QNhO8ayG05Q/zI0MUtclMmI0/wB/gmQwoGcwSxiRz3G6LFLX8KB9EpP
         DlLwbYnrtjMQvRs5ntzCbt4UJPUDpjX0+jJcdcfcIKv1yqZ6f3IvZNmeAdPvwlYiPVWG
         wcySK7+bXFuYJNlU1K7AnF3y7L1SAhlh/NQu+pMzxL/yPGQDgA4c4+rTTgOHEEnL+IL7
         z5Ew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700127736; x=1700732536;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=zgTAA/fXkhuI+SjSIxB1KcceCAukG3MIFyZlQp6TERI=;
        b=GYfutTBHPKygzts7ft0O3CjbBSyW9KcvsOXO2MLK30olA3a4cpQxHHohommH8cSS2C
         cwoHE3Dgvi4DBAvCCuW3LZ/7838LZlnGPQtLhXjonMm/CIZvQ1Zw+BJ2vTxFi1HrGGm+
         ckXkvzi76ni/NFWPLEdmNyr69HUMvKp88pOQb0TKR6zSzIPRuznUGrVWewIp03PcRlOY
         HARkrx4tvvs7lCAz7xLADXk+knSJObrzyvE3W2GtqtzcIBHIo5HDoB2mgVvvN49bLq/c
         uCvX8GMJY9SkGAKHzv2cQ6DbciFKMmMqDbkIihRIawmAayht5Oo8CMN6JJU9otnOT2rw
         I5Ig==
X-Gm-Message-State: AOJu0Yz6HRoTggnBY46yQxp0cEBt28NdqSxVqLXygkHcN8aNJeleI/9/
	69+0CNhohIrjCHF8NOf4aNU=
X-Google-Smtp-Source: AGHT+IH0Nl9sicA/TLaCAIle3cI0aBxNJAGXYq7XJVqPe09NucNbDDo0OotwJRBLMA/tfntEY5CF+Q==
X-Received: by 2002:a17:902:bd4c:b0:1bd:ca80:6fe6 with SMTP id b12-20020a170902bd4c00b001bdca806fe6mr1462650plx.41.1700127735743;
        Thu, 16 Nov 2023 01:42:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d2cd:b0:1cc:eba:de19 with SMTP id
 n13-20020a170902d2cd00b001cc0ebade19ls494027plc.2.-pod-prod-09-us; Thu, 16
 Nov 2023 01:42:14 -0800 (PST)
X-Received: by 2002:a17:902:e74a:b0:1cc:42ec:9b96 with SMTP id p10-20020a170902e74a00b001cc42ec9b96mr9391998plf.45.1700127734316;
        Thu, 16 Nov 2023 01:42:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700127734; cv=none;
        d=google.com; s=arc-20160816;
        b=bZwy8F3e517aQJjS/Xvu8ljeNTcUHAnPv5fdm1Re89iwQXRi04iUpA667ot224tF2v
         MXY8qew2PkjKHPOwHkAUT3iLus+GVBYwr+4+rvUvhM370gp2YlL1gqLYDFKs1kZBvBZ9
         w1FvsWCLJFv9FP0sM0TFV1kbkmYv72zhthX//QXTVWiGJU+J3nStxVXaSVI0zDrcn1hp
         QlMlHgcYTN/nQ402CTfScyN2JQJ6+Htzeq7io29D7kLHep/KN60JhxWV/aVeyInOoHMl
         uAkSMXwxmQDFymAu7OENhLR2aIIt3EmS6HoQt6q1Yji2l/YrDXmDwU0Ih+ePer++WWhn
         qtRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=HbQBUq6zMPZ7ORs1zmLeLhmCeGDS7R7Qw733eYdaWDY=;
        fh=YZa8vkdUz4pzRj6QFVU/SyYW+LsIH/Wz0o5e5dUhKFo=;
        b=MHtOlmNoIVZT6/y38T1LTFagwW4NAy2WaelNw5RRIL91N0UajSgc928n4VibzR5/9C
         deIt0csGM8SZ7lHXcixxCd0IgSSnBJ9wXMpkMx0SnsGIcSEGU9FloXZCEDrEkSLqhgEp
         F4ySo1upQ9Nocg7h3MemSWEh93GFpkezO26/K3kaO3Wjreav4wrt2hj+3r3vonyatuck
         EQ2I/u/zvgHZRLzRRNdP4Lm6N8p/+KjScshgLmE9IAfwtBc8i6+PMVFbp2gm0BuGfrMG
         Js7iWbYwi+sX67Nxxb1PBCvw6xgIsLABG2v2U2eznlHI4BpzNOl+4u0aG+DWqjWI/yNs
         DJOw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=S2U4U74q;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb35.google.com (mail-yb1-xb35.google.com. [2607:f8b0:4864:20::b35])
        by gmr-mx.google.com with ESMTPS id e20-20020a170902f11400b001cc5b5f692csi647078plb.0.2023.11.16.01.42.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Nov 2023 01:42:14 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) client-ip=2607:f8b0:4864:20::b35;
Received: by mail-yb1-xb35.google.com with SMTP id 3f1490d57ef6-d9cbba16084so512810276.1
        for <kasan-dev@googlegroups.com>; Thu, 16 Nov 2023 01:42:14 -0800 (PST)
X-Received: by 2002:a25:c70e:0:b0:da0:411b:ef19 with SMTP id
 w14-20020a25c70e000000b00da0411bef19mr14634881ybe.1.1700127733310; Thu, 16
 Nov 2023 01:42:13 -0800 (PST)
MIME-Version: 1.0
References: <20231115203401.2495875-1-iii@linux.ibm.com> <20231115203401.2495875-4-iii@linux.ibm.com>
In-Reply-To: <20231115203401.2495875-4-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Nov 2023 10:41:33 +0100
Message-ID: <CAG_fn=Vw-kR4QM8jwJYQjv8ma+mh8uyGyP2SP7PhoMvn7UqYwQ@mail.gmail.com>
Subject: Re: [PATCH 03/32] kmsan: Disable KMSAN when DEFERRED_STRUCT_PAGE_INIT
 is enabled
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Marco Elver <elver@google.com>, Masami Hiramatsu <mhiramat@kernel.org>, 
	Pekka Enberg <penberg@kernel.org>, Steven Rostedt <rostedt@goodmis.org>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Christian Borntraeger <borntraeger@linux.ibm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, linux-s390@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Sven Schnelle <svens@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=S2U4U74q;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b35 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Wed, Nov 15, 2023 at 9:34=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.com=
> wrote:
>
> KMSAN relies on memblock returning all available pages to it
> (see kmsan_memblock_free_pages()). It partitions these pages into 3
> categories: pages available to the buddy allocator, shadow pages and
> origin pages. This partitioning is static.
>
> If new pages appear after kmsan_init_runtime(), it is considered
> an error. DEFERRED_STRUCT_PAGE_INIT causes this, so mark it as
> incompatible with KMSAN.

In the future we could probably collect the deferred pages as well,
but it's okay to disable KMSAN for now.

> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DVw-kR4QM8jwJYQjv8ma%2Bmh8uyGyP2SP7PhoMvn7UqYwQ%40mail.gm=
ail.com.
