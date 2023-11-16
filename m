Return-Path: <kasan-dev+bncBCCMH5WKTMGRB6WJ26VAMGQEBRLPBOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id D4A7A7EDDE4
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Nov 2023 10:46:35 +0100 (CET)
Received: by mail-il1-x13a.google.com with SMTP id e9e14a558f8ab-3594fa6ef2esf209785ab.1
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Nov 2023 01:46:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700127994; cv=pass;
        d=google.com; s=arc-20160816;
        b=PPte9rMeXEb4yzM9kN/0rVNkjdVt2jU8X019b1Vz/EnspwYxQu0g/YrEsMAOiCwQgo
         GHqZQCf8ai4Df+zyWqdgp926too2qLxWDPHbMuH9/Krg/W4+DzkaYOpSy33Bne3EWU8d
         P8MtzDSD78VvcOJKPIVSvyKX7m+8IoNyf1OFRMfZsFvFIwdiVLJY94B57a8vh+mNO1TZ
         HhhfR3GzUwrTp10ybPzFN4uFWUuV7zzfzx1POzXDVtQa/yPKrMPsW3ZzQXOmFyNGUqmL
         Wr2RZMlOvlhq0wuEQP77dCS54Zj2ORtYKb2i+IGwJoDztrm+DrcwOo89ohjWZfcf7jHV
         D1AA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0j8/o2O/bcM+89Fr3pjTDNQL9k5B520g0gw5R/iAE/A=;
        fh=YZa8vkdUz4pzRj6QFVU/SyYW+LsIH/Wz0o5e5dUhKFo=;
        b=UG8ndHRb6razTbfuQAeIcNAZMHvr4dkoMos3bma2LYtUlLUarfDM/W53jOtqFFQXx+
         MfTJXYgJY9CBSprPOUVt2/fL+M+7atilNqhqz1ymkyHWEAI8aPuygGYHseLlWWqxs7qH
         gANmUrg4d72oDsdum7ywNO7Vh/LYEQzbBxwXV6W1dUDsgXvRtzMeS928Oc4xZQiXwQGB
         GjnAA2PMjCedrb+900YnnYgxCEW3XexqE8o4sBjV3/ZoGfeF62D8XosDpRIG0V9atzoE
         a/Vpz7bieAFB8SuwuGdrFW1Gxp0gl5z60aZCTWyGzrCw5jG1QNLACNaD4GfL87sladCz
         IQ3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=NyTnv9rI;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700127994; x=1700732794; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=0j8/o2O/bcM+89Fr3pjTDNQL9k5B520g0gw5R/iAE/A=;
        b=sDv8BXKVsawQitE7bA2qwwdpIYFb54xg+PPNwDDiqcVVavRnuH9JGsjJS2DjEigM+6
         EtW0xeXfYqNFiYXI8LPr+F8NRb4RTiOL77defY0tC5CG9N3iVfNBuRckKzY2BsVrrdsu
         CkDE0poNFrdzM8ssT0IvnhAhvWLHi3g+yW5jYBMjqkZg7d6pgRUwbpriT713bgK13U38
         em92PcKY3PwyN4FFBxHqdaYzp1u5HG9ADsG4AO8ZWldHnHNue8Yl8ppEDEHI/MXJ/8wf
         krpxPbmk8OmJEnda8oy0uWur4s/KR1tGshTXQ+FKKohE9HshgT0Z942LVUaCf+HFYsv0
         IjNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700127994; x=1700732794;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=0j8/o2O/bcM+89Fr3pjTDNQL9k5B520g0gw5R/iAE/A=;
        b=X3i5TIH1tKztxXgOLJuZ1GD1gEPafxujuEOJXV9rPu1qhSIyZvfsIRvfSqe85IM0NA
         OR9B+J9C960AYNSq9PiiRUSg+wFxm9CCnL7D75Ti5OtOv6OvjJdClmrSuG+dRfANSehr
         HdTALJEd/JLlYiBwECMETwVEYkxiEqQaVNsqKy8/SbmiFksfrLAuWKCfOBUPHyeUvlUj
         thVj28x5+KCGHT3A5mXHu5JOkRZrc+AIKxo/zF3DnmJOmEIHtgmfJOSh8wJ5us/qL008
         OnNELdMxJ+MrCvd5SSKgHVYxE3OKVzfdqvtKAeAcA4VJNYdGzd4K2Pro3qNxZPAlj/gu
         Xn8g==
X-Gm-Message-State: AOJu0YwM8BtyQGSqDvVmBBJROD69mlu8r1TDO9/iOkY2DCa8NLctLW/7
	q/uklEozdFpYt1pxnFIFprQ=
X-Google-Smtp-Source: AGHT+IGGzjmOjTyHAVyV4nXFiwYMvlsDqEMiiYKFpbAKAyroINXgNxaHFaIUz4H/1s09KGk9g7qDgg==
X-Received: by 2002:a05:6e02:1907:b0:35a:a594:1abc with SMTP id w7-20020a056e02190700b0035aa5941abcmr196476ilu.10.1700127994457;
        Thu, 16 Nov 2023 01:46:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:d3d0:0:b0:357:af8c:6704 with SMTP id c16-20020a92d3d0000000b00357af8c6704ls395786ilh.2.-pod-prod-02-us;
 Thu, 16 Nov 2023 01:46:34 -0800 (PST)
X-Received: by 2002:a05:6e02:1aa9:b0:359:5389:c0ea with SMTP id l9-20020a056e021aa900b003595389c0eamr20585205ilv.1.1700127993815;
        Thu, 16 Nov 2023 01:46:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700127993; cv=none;
        d=google.com; s=arc-20160816;
        b=eIEvQCVEIUJmlmaq15R9VbP3FfFsttYrdJZwskageFS5qfq3p5bKwLzGmmEMPrsF10
         qMPIcCTGF7/FgCQ8QBZRm0JWVwtPIWsW/vq550beL2eie1tkOPq+KnTtRjZLYAznCxxA
         KVoDdWnxm0JBOqN58BDvhSyzAa77b35jcnB63oDQDfb2ZIn13w/3Z6YE1IDplkpa/DLi
         /+tPHaT0eg+NOJbMTWsbQPm/41YZ85Sr6XC7GUBHB8KETSg+pBXTmzPSCtbwfWIBIGJ0
         Df+apsjZ3MwpISwDvWQSgfht3cyqdo11cpHON01YuF0xQPZwQSiP0KOQVoceuLLMWwzT
         e3ig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=y2IE4TMhLsEPKM/hSail2p58dx/qbJfsgHuokbxSXhI=;
        fh=YZa8vkdUz4pzRj6QFVU/SyYW+LsIH/Wz0o5e5dUhKFo=;
        b=fj8UhQsB9ViQBgfPZqY/bEB2n3kupNrUt48uEJ2AbVUKEHeSuSeVlpIBfk0jLknzRV
         m8O0Ftx4LWotEXwa9C2Uy2dHywbs2uvpF2lE/09fDfDWlD5SjQxGO3kywyFem2twiBiH
         hfxL+AHBP7BDwJXnZglxyU6SvLNpFpnesT217gBhmGP4/RDvH8Zpqs7xxADQuF1ThL5f
         AjfXHaQDlHUPV341oFCWS2eoZn/Q3cVLNXsGx6Zinz7liICcXivDUosxBCfsq/thDWTk
         ENJTqQnrhy/UMz81VAoT3PHsVdkoXSVwpuy26BP/PRyuvJM9E/xOfaMA/NysmjiDHVD7
         oU3A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=NyTnv9rI;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb35.google.com (mail-yb1-xb35.google.com. [2607:f8b0:4864:20::b35])
        by gmr-mx.google.com with ESMTPS id h27-20020a056e021d9b00b00359d1e22f06si1162338ila.5.2023.11.16.01.46.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Nov 2023 01:46:33 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) client-ip=2607:f8b0:4864:20::b35;
Received: by mail-yb1-xb35.google.com with SMTP id 3f1490d57ef6-d9caf5cc948so551153276.0
        for <kasan-dev@googlegroups.com>; Thu, 16 Nov 2023 01:46:33 -0800 (PST)
X-Received: by 2002:a25:ad27:0:b0:d9a:5ff4:cfde with SMTP id
 y39-20020a25ad27000000b00d9a5ff4cfdemr15547906ybi.13.1700127993266; Thu, 16
 Nov 2023 01:46:33 -0800 (PST)
MIME-Version: 1.0
References: <20231115203401.2495875-1-iii@linux.ibm.com> <20231115203401.2495875-22-iii@linux.ibm.com>
In-Reply-To: <20231115203401.2495875-22-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Nov 2023 10:45:57 +0100
Message-ID: <CAG_fn=UyvxneFvXPyWhsiKQLrRh0aPpPKORh6J5HJ0t2ZHo4jw@mail.gmail.com>
Subject: Re: [PATCH 21/32] s390: Use a larger stack for KMSAN
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
 header.i=@google.com header.s=20230601 header.b=NyTnv9rI;       spf=pass
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
> Adjust the stack size for the KMSAN-enabled kernel like it was done
> for the KASAN-enabled one in commit 7fef92ccadd7 ("s390/kasan: double
> the stack size"). Both tools have similar requirements.
>
> Reviewed-by: Alexander Gordeev <agordeev@linux.ibm.com>
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DUyvxneFvXPyWhsiKQLrRh0aPpPKORh6J5HJ0t2ZHo4jw%40mail.gmai=
l.com.
