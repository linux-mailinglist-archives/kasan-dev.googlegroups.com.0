Return-Path: <kasan-dev+bncBCCMH5WKTMGRBA4KZWVQMGQEVYVBBMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id C379280A8FF
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Dec 2023 17:32:04 +0100 (CET)
Received: by mail-oo1-xc3c.google.com with SMTP id 006d021491bc7-58e2b7e4f94sf2488341eaf.2
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Dec 2023 08:32:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702053123; cv=pass;
        d=google.com; s=arc-20160816;
        b=DDVLR9OdKKfr+88XCJjl8sGvdZK7of1Mv25JTwB1Ra7/pn58woZvvu0dfGadCVajXa
         eD6xnbdpPWlzthcMkKYbbm8rX4t86dlf2mHaxMtm4tr8Up3bcDYGTuzVeWY1FS2UqmbA
         X/jiTB56l86dNwaNoE3pMbn1x+cJNgN+lZEyz+I0dRl361Z5igC/vuGt0/DG7ZckI+Wy
         k1Z27RZnZLgR0Xy7PL6lwyFJ19Uo2yovhRLBMwdzcgTgBkIeteAJwbuFfonv33nDRIrQ
         iHCLmBt7+L/d0YzIss0hbSH3skzriopqvr/nFnlt/1agid1kqHOl3fI6OMHmWEnBbvdd
         gX+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+sD7DM1SPFhHpuuY/p3kVl0gNV28tmDgzSB9zI4dHAw=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=RDdQ5TZAj0rA/Nk4YXZNuO1TBtbPN3iawl/FkSdeIk+FPcYtqSrmDXcATNlthbaUK+
         /qe4Cmbwhj6kRVbzWReQGJEsTfmQnOZYYHmUv01rmzjXjeqN+sPWbqqCn4yyrec+ERaB
         2QZOTWt4EeRej4WBbsw1/IduEhqu7sEnnLg9oMiDtelVyhTG3Pn1sz+8njU2X8dhaqKn
         msYMKL9xk7JcV69G5sGZK5S6k0i2qDS+IH4oRzRo5v+uXfOgb6o9u9PancZXEM61sUDW
         CziJ5o7LfMDQ+9oqBn1ZXIBqYVPyeIib6FBqNNpLmex+vKkl4ur4wYJOwdJaudOMQLzv
         Qw/A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=MdafJ8Hi;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::c2b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702053123; x=1702657923; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+sD7DM1SPFhHpuuY/p3kVl0gNV28tmDgzSB9zI4dHAw=;
        b=IqXHC+nTvSnI+F6cHB9YcQCnuMYTnwBkovO0Rjq5qRyCqRtdop8EfoUZXD08aaopb8
         Znk2LFRU3DTbREHmDVec08g/G2boRNndP2BpTbhE3JUUdLYDac0zKYspDbmUhy80rvHQ
         rAhq0TCYl5Q6YeRCgUrxi0rlVa4Yd1t+wcfzLxBrR2LrnUOpCPfwtXqAV1n0bNvf1YwX
         /E/UyuU4LeWAscMjL7B6pwPokq6rjY+i8QasNq7mayUSUf1B26cM3KU3OWLIimFQ/6Ro
         RV6QptH/g6fFn2lREIJ+YsZM2A3IihdozAnTcNGWDniG9N2fZSHlRZEGl0pv1HsOfla2
         4R4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702053123; x=1702657923;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=+sD7DM1SPFhHpuuY/p3kVl0gNV28tmDgzSB9zI4dHAw=;
        b=c3C4J7rhJ4gqiZD7MY4MSQW3NORbSzvU9J6rMl8AoMWxPYfkMLhoEPRr/JkENcZ6ji
         7hxUceVVGMYw5Hjw70XTuzfMsuRGDWFVwh0FsX8cBIRbHlgIwp5POI+yUjqiMP3c6NN4
         rWKV2ihhhsn2KQ/PEiYOgQvKgyx0XSunBhKzKrLTXCGUUAWVLQqGUGepswy4xDDkmUVU
         GWD5tt94uAhdM6wnTcTA4JfK57JifvPHQmc0qS8y1Wb6x1+50gU9p2wA1QTykNtVhqo4
         A3LwUYgAMpXM37cpUbr6BXkdGxEUyyde7Zz6er2To3g0WQhGHJO0CIIdlPyuer5R0kOF
         hdlw==
X-Gm-Message-State: AOJu0Yz6NsNSiXo2rtqKtG0cGVXQ/QtxX1jYpdKNcMRB5aCNrpOGLoel
	oP4ye7bXTJ1HYhRGFvDl5Vo=
X-Google-Smtp-Source: AGHT+IEvVeL3P6azJ1BZGcJCDn4q8k03y1rj7nfJxgbXVY5snFnnHxBP1yH/lUCyKHDIK3TKjMIZRQ==
X-Received: by 2002:a05:6820:2305:b0:590:66ca:30bd with SMTP id cn5-20020a056820230500b0059066ca30bdmr446080oob.15.1702053123610;
        Fri, 08 Dec 2023 08:32:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:2224:b0:58e:2769:6234 with SMTP id
 cj36-20020a056820222400b0058e27696234ls941353oob.0.-pod-prod-09-us; Fri, 08
 Dec 2023 08:32:03 -0800 (PST)
X-Received: by 2002:a05:6808:3a16:b0:3b8:6422:5891 with SMTP id gr22-20020a0568083a1600b003b864225891mr324687oib.20.1702053123051;
        Fri, 08 Dec 2023 08:32:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702053123; cv=none;
        d=google.com; s=arc-20160816;
        b=FAAkYn7Q5G5Le2Mf7U+LGK65/csHrcwTQFcj7T538kqU0LsOQ+UpMrN12u3aQQud0y
         Gr27stmt3E1HR2OVJPOM/ZO1EF/sR0av3ImzYdL0Bt6OHkLUQ2w74vYpZZw6Ttagnbbh
         cai7bHT7sOYUhHwbqvLjMc7SpF+2A9uVPcrwxo1dlvR3hp4AGxiBLpSc7rIjT9l3JZbt
         E6krRbqUXgyH5WRTRC/d+zMVdbqHUgYDY1jZrx9IGWUqTevLlz1I/ia2tH4d+oDaOv67
         WdI/vR1Rtpcw7ELw5ncrEfaKQGBSwJl1Xm4pWzlQCqMDZvPRP7eIcJxKoGKIbv/MAJnQ
         vbCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=8sqOsISr4A6CIOB02HqyYbsWnQIUDQQ0cX4xtpbDCng=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=tM7DylcNyaMW5WBbabDLOY0iW9NzWAlB/GRusw+mE5rKda0OlclYODp9tS5cJ5VCvc
         /Mk3WqGjxq2ex6DMHjhjVwdj/FZTABmGbilGrNqWPIOEKWrCtxmcihFURKXauapeNHaI
         MtyTBH+BGRhTYpOwahjtXtolEJa1uENf5W4UT5IpC2Rhq9fD7WyqMB9ip3N9KAxdLKI1
         JPzl/PFHQP/Ci0iK4gJdQUj3VcRpy8+xy3Yf2Ni6Rz69RW6AqfGImxGKXwC9bUMr+msZ
         S5pnBvsqhWjc6F3KBDEzkS9pixdU6DgWJumDZOfubipWHhmO12ab8KWP5bwdGi9EK1C+
         jE3g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=MdafJ8Hi;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::c2b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc2b.google.com (mail-oo1-xc2b.google.com. [2607:f8b0:4864:20::c2b])
        by gmr-mx.google.com with ESMTPS id fz5-20020a05622a5a8500b00423e5a4fb24si494488qtb.0.2023.12.08.08.32.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 08 Dec 2023 08:32:03 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::c2b as permitted sender) client-ip=2607:f8b0:4864:20::c2b;
Received: by mail-oo1-xc2b.google.com with SMTP id 006d021491bc7-58d08497aa1so1141681eaf.0
        for <kasan-dev@googlegroups.com>; Fri, 08 Dec 2023 08:32:03 -0800 (PST)
X-Received: by 2002:a05:6358:7f13:b0:170:2c2d:9d8f with SMTP id
 p19-20020a0563587f1300b001702c2d9d8fmr209508rwn.1.1702053122541; Fri, 08 Dec
 2023 08:32:02 -0800 (PST)
MIME-Version: 1.0
References: <20231121220155.1217090-1-iii@linux.ibm.com> <20231121220155.1217090-5-iii@linux.ibm.com>
In-Reply-To: <20231121220155.1217090-5-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 8 Dec 2023 17:31:26 +0100
Message-ID: <CAG_fn=W_aH5a5grk63Uwx0Dq-dvdafAriBc3v5YtYA4cXiuJ7Q@mail.gmail.com>
Subject: Re: [PATCH v2 04/33] kmsan: Increase the maximum store size to 4096
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Heiko Carstens <hca@linux.ibm.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Marco Elver <elver@google.com>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Pekka Enberg <penberg@kernel.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vlastimil Babka <vbabka@suse.cz>, Christian Borntraeger <borntraeger@linux.ibm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, linux-s390@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Sven Schnelle <svens@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=MdafJ8Hi;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::c2b as
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

On Tue, Nov 21, 2023 at 11:07=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.co=
m> wrote:
>
> The inline assembly block in s390's chsc() stores that much.
>
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DW_aH5a5grk63Uwx0Dq-dvdafAriBc3v5YtYA4cXiuJ7Q%40mail.gmai=
l.com.
