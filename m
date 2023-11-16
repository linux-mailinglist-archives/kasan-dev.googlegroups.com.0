Return-Path: <kasan-dev+bncBCCMH5WKTMGRBNGJ26VAMGQELVAPGNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id BECBC7EDDDB
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Nov 2023 10:45:25 +0100 (CET)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-1cc52aba9f9sf1754585ad.0
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Nov 2023 01:45:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700127924; cv=pass;
        d=google.com; s=arc-20160816;
        b=WyvM6RYkiw38G0gZ7tOS4rtKnOEceQQO9czWvbkxaBXocd0VIailKP4s+MsVs/+YNW
         a1HXeUdp+PNFHWY2bB5GHHx0fd+ceHD+meYSI8tNezK36emMV14geYEGGOZCzJyHHCOj
         8979xkke4S4GQylfKD4VazvIKRqUmlWo9sQnIYgTCmrYhbCJAjp+Gzo5uS/GyN1u+f23
         indL/BdD7K4kMQLbYJc0sz5Ad0zSl9erN3umFJy6lbZb/WjGBTEu83E24ldT/6cuu7cL
         871L1X61DNV9ExkvHnWqGYygjxEiQGBfXbf1oH7RPNerO2TnFmhyC9ItB48Bk5ffKxpj
         VsGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=iEUBsg32dGju67J9aD4zK/vAf0RCTkwvyln1T1EVdXI=;
        fh=UXa0+IedBzEB8OeYgMqdFQhpgKhMtN9dWMmBytHNDZY=;
        b=Ke4oWY++dzIqTSBpklWBubCzSdg38mP4OJYFniCS3NVgTbfXrTtVqrpRlQntVhqiM7
         ZT+ilGo4S9OqvVWztaSqDhfLcOlI8kiSuU2bX6EvFwHKgpWVKBIz5gmr8GvnMy54TQiR
         9xrq8yG+mElKP0jP6OIftmsWHbYsvfEhdZOhYqoVWt4Bqw+fJ+5zvfBVLkWiK0s1b95q
         FVig8SgflQMNrq44n9TXyrsvZ4mCbksmUg09LKy3690hMLmsnL41sB5v4NTSP6nva78q
         OxUZp7yLGm6PXyrzYpVUkGfiToEXePw23Ed7uu3nLqoBoX69MSvjViSZfoKIXUFIQPzf
         WlNw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=H8iyZRk4;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f29 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700127924; x=1700732724; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=iEUBsg32dGju67J9aD4zK/vAf0RCTkwvyln1T1EVdXI=;
        b=YFP5dgjAiRTUfDpJ+YHG2YQXyZ09gqXX5DA2FHZWNcJTaHPRM5sbfRH6vDjwydIfOx
         weObTDHOV/VV5rCw9AuksLYlGy47pSj+ReQHK6lvq4b7MSGjyUxV6Ydd79oQ1isc8uBv
         seLbJHpvEaURF7bXCCSROSlADxk49sO08QSmWpREn1o4jbDXFIBE/zoFbhFE08I+JWsf
         I+oC3I1cstUTqX4ICQD9NUahxs54u/4Ozu7at1o29gUeG3fxtq/TRjrZ56MZN80RjnyB
         5w2w3rE450DbyRJVheMCzthCAnjya/WmslpxtzGD1dDPdYrj5XlBl2Nw5N4/I/5IqLjF
         3Bpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700127924; x=1700732724;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=iEUBsg32dGju67J9aD4zK/vAf0RCTkwvyln1T1EVdXI=;
        b=lvOG2MU2Ztw/BzBRZS0HFA2VJqJcofb2wyn0NgS7Mk+sH+FqipM1xLWqNp/YWgq7+j
         SbcveGwjj2dZB3iwHMLrWjVkg2INfL6b4GZFdvEZ04s7ksKdCauj77yZeHBkN1Rp082b
         1FOsvrqgRu6F3kKuV2NXLUnvbuv0Ae6lLJb+8wb0mV9yhEWUbV64slyOiZ+ETKCnszuI
         3X5YHXrXeINP3tHBdc2aJm8jhoVNrzZmftHfj+qiyedX2okcg9ZI1NbwKWcOvf3vPC+3
         wd/CxHXvidSwyk8DTX7jJxEJMDgU+bhtQMUXk5rV/HzDeGpKXUCZFMtPS1YYeQNLBKTK
         8a2Q==
X-Gm-Message-State: AOJu0Yxv660gTO7qsgKgL3ERC3Z77i01OKgS5d/FJXqR4PNsztwnpT3o
	3jNv9AqkpH24SrXnAh9oBDU=
X-Google-Smtp-Source: AGHT+IFICKdfqxLUwVmgZ8W9+4/R6b4XGR/5BJV4OZtzIp2Ci/A1PNtLSR3PhUPrxsvgnOE4aNyD0Q==
X-Received: by 2002:a17:903:2341:b0:1c9:c747:459a with SMTP id c1-20020a170903234100b001c9c747459amr212475plh.5.1700127924281;
        Thu, 16 Nov 2023 01:45:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:9a83:b0:1bf:1a9d:bcca with SMTP id
 w3-20020a1709029a8300b001bf1a9dbccals501121plp.1.-pod-prod-02-us; Thu, 16 Nov
 2023 01:45:23 -0800 (PST)
X-Received: by 2002:a17:902:ccd2:b0:1cc:5d06:b38 with SMTP id z18-20020a170902ccd200b001cc5d060b38mr8472403ple.64.1700127923212;
        Thu, 16 Nov 2023 01:45:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700127923; cv=none;
        d=google.com; s=arc-20160816;
        b=x/SbvilyJiBLuF/VY1En6YHdPWEoI/VmQBOSeE/+MxbA2RhipvPbi9T4DfjDyxUhkc
         Pyp4hF3+B8yl9WACU+JSvip46n/fhJKFTpm4A6E8OmINbJuktiXRtFkunyb5vcZnLQFL
         UCkV6kvfN7jjwrt3TfLz1QoX3RhslkDd79lgrioZVUjnUDFXubZFjCyW3ZrjuBW7kEXK
         kdhtBvrlJH6/qqZuCXXo/FvdLwI/iK4x/6xXrrff/cEnRu9mzYW0NTXxNFp+DfdIPcoe
         kzdMNU07ymQkdBZFriD+Nyg542dEznh/B4DxfutcQ8gU91R/1rGSISiAGdD9FnmviPb0
         bcbg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=kuV5LSK+LTxWeRbqVFyqwK6y6J/MVZo38WZUFkMurd4=;
        fh=UXa0+IedBzEB8OeYgMqdFQhpgKhMtN9dWMmBytHNDZY=;
        b=kU9tlu8ZDMWi2yoSx+CwJ7b/QLaBbCWz0C0AcBOFDDIMbrwlA8oX5yXCEshbFxvmxB
         EvMPc6apmBkrJT7VNwxU3Yy92rRYh+pSc2DoQNI1UuL//w61aB6+pRHvnvvA+58gRQaA
         06n1xL3rrsRcCLgeXu4S0n98o7FLeIBJfmdpPFBU1xm3Gz/qqU24wtOo76/NrxB284SL
         018vZ3HmA4Nz3SIv+8XfBxZjPMaFUIvgtVbi9QJ0HTV6dxy5XThA6nPHM1VhF0XVlMY/
         fMtPAI/17NWTlE726h8S+vjcA9Q1RIkzbdZ+dgDReFwZPscG20vuPYzWoEcXxQDeZLbg
         Uhqg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=H8iyZRk4;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f29 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf29.google.com (mail-qv1-xf29.google.com. [2607:f8b0:4864:20::f29])
        by gmr-mx.google.com with ESMTPS id b9-20020a170902d40900b001cc55bcd0f3si566314ple.1.2023.11.16.01.45.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Nov 2023 01:45:23 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f29 as permitted sender) client-ip=2607:f8b0:4864:20::f29;
Received: by mail-qv1-xf29.google.com with SMTP id 6a1803df08f44-672096e0e89so3066646d6.1
        for <kasan-dev@googlegroups.com>; Thu, 16 Nov 2023 01:45:23 -0800 (PST)
X-Received: by 2002:ad4:4d11:0:b0:672:ab2:d9d9 with SMTP id
 l17-20020ad44d11000000b006720ab2d9d9mr8242754qvl.29.1700127922512; Thu, 16
 Nov 2023 01:45:22 -0800 (PST)
MIME-Version: 1.0
References: <20231115203401.2495875-1-iii@linux.ibm.com> <20231115203401.2495875-9-iii@linux.ibm.com>
In-Reply-To: <20231115203401.2495875-9-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Nov 2023 10:44:46 +0100
Message-ID: <CAG_fn=U8r0cZ2ZG5dr-Um9Un=S_go7-PixFXJ-PkXCMyL7VY5g@mail.gmail.com>
Subject: Re: [PATCH 08/32] kmsan: Remove an x86-specific #include from kmsan.h
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
	Roman Gushchin <roman.gushchin@linux.dev>, Sven Schnelle <svens@linux.ibm.com>, 
	Heiko Carstens <hca@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=H8iyZRk4;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f29 as
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
> Replace the x86-specific asm/pgtable_64_types.h #include with the
> linux/pgtable.h one, which all architectures have.
>
> Fixes: f80be4571b19 ("kmsan: add KMSAN runtime core")
> Suggested-by: Heiko Carstens <hca@linux.ibm.com>
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
(see the comment below)

>
> -#include <asm/pgtable_64_types.h>
> +#include <linux/pgtable.h>

For the sake of consistency with other KMSAN code, please keep the
headers sorted alphabetically.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DU8r0cZ2ZG5dr-Um9Un%3DS_go7-PixFXJ-PkXCMyL7VY5g%40mail.gm=
ail.com.
