Return-Path: <kasan-dev+bncBCCMH5WKTMGRBQE7YGZAMGQEZ6DGTQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id D3F6F8CE24F
	for <lists+kasan-dev@lfdr.de>; Fri, 24 May 2024 10:28:49 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-43d48e8f0ebsf140771cf.1
        for <lists+kasan-dev@lfdr.de>; Fri, 24 May 2024 01:28:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1716539328; cv=pass;
        d=google.com; s=arc-20160816;
        b=ppqHUvjMQckdvXO7IMC/tTMLGQqmql8Rj/agDnFsLCBONAaSo5yEeiqo1ZEBf6iCbf
         6QvfQSnF/906BAVO2aw1U73wBsZwfLuXT08HKkpLRQN1vlxWd7wxq7wWyku4AwQ88iR3
         ccQ1MLLgYqIfIBaQ01v/tjrax2AAaxCsz85wSi/E3MPha2goq34o/kSP+SKpsEM53HbH
         GV9apZtx2tbl5yp88SOVkasdRcSu8SFHy7VaReJRd8fhudiQRh0Vh74/+oMXDZLZnizt
         twSNnIAtdTXsf4ORK8qNLTxa6FpkOwz26XGUC6xbfkvaFsM5siEneiq7BkDlRal94TB8
         YmDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=MUwU/FCZCMm5aFS4wKBMP+ie8RAh42LsEY8RqBGOEhA=;
        fh=+FQs4JjXiOtrwfXdzSx7eS0jL4OoE1vTwxpNBlM1cj8=;
        b=SvgfyJ0tX1wH2ZHQan+nIPUXQSmnRukGZ+CJT5y1VN0FPSdrN2v154uUOK4KXz7ftw
         wXL0c+qznsGg+DsK97bdY8HtRciJcYSAlPa7nwlrn2ltBp+x4MwevpPjJ6gF1Y+yUOeE
         oZhP/EN1ooquxtyJPFEhi5RbncunByvniCLfwXang9SaaOG8KvwJ1rGruA4dj5Mh9Dpu
         5BE+y2q1dJFydjyzt0n2XlB1DHpIiqq+3iVPzRDv8dagUXr3oDXJGn3k9lvO/lLehFlo
         phsUMknAar1qEQoDwP3LlwoAwJhfKKYgvqH8BUeEMwBxXZL+azYImbE5mYS/LSBlVoYw
         CRQQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=YlY2WbWd;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::830 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1716539328; x=1717144128; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=MUwU/FCZCMm5aFS4wKBMP+ie8RAh42LsEY8RqBGOEhA=;
        b=cnpT+Pk23d7dBOA99ih87u0am3HKcuNilJlg3ecyloDvj1+6EgMv63SuO5BdNukwrd
         fKaMYbDzyZVj2xkW36yAxJXmsGxHU8zFtKz1EbKku+taY+KmoipHOf3tM4fxpTicmI17
         U+Nqk9PDlS/0ZamVKH8HIWt608o5KkTBA6QkvJD+ws+BgIkKxt1KH/snlfh754Qg91kr
         r6mjri765gjWfzHvsudqHrm2h8eRyKH7VZzNxvrrxqehLMNn2pkPpfLjNXphFfNlIFua
         rILqFplTs4OPDhzluL9yV5FJClM1qNjCsimA7zyYubcWr5CAPu58Dp+dIYi/tv1Gjb56
         Ee4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1716539328; x=1717144128;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=MUwU/FCZCMm5aFS4wKBMP+ie8RAh42LsEY8RqBGOEhA=;
        b=RQNG6g3KekFF5e3njXkLE9PKFdtfav9OOu88HmVZmRtPayvkoVr3/yeWZG6plJKnIN
         xCRm0hYD67E1NRmkuxvNV33nrHsTh3wVg2pN9R8KIzfJwWeXKsJcHTQT61z56Su+zlC4
         fffyQeLJBNTqNaUXYlQWdBxV/Xlwt0qHgTupCwy/EgMGELC9DXNShxKvct3XbLnekGy/
         ixDPFpWD3gBxmBeo0Oy8EWIbzCpzZzBckl2dCaTsD/aJ5S35XdwzMEkYrfX3i242riGq
         6SvBhJUTXhSsc90oD9EhG6GRfV+vz8+GuRRx5vYckv8lScGfjIV4uxnw4uwssDXJ+y2T
         D+LQ==
X-Forwarded-Encrypted: i=2; AJvYcCXBe7rjYrsxpxTPUT3hI6iLioRZdSJSmPp0jh741UyghSAB6Pfjyu3G7YFhCSaIElFNb/e63Mtjha+i43dNtHLccS8ujYqC5g==
X-Gm-Message-State: AOJu0YxKt2v/UAKObr2QceILBJiDcfoN7/UNtsbxpqTCukQo6MVufd4E
	f/tm9Vf40mKmz7UE6NNqzF3WI7SWy/9oDB4SDV/2pUJkVPDiL+Xi
X-Google-Smtp-Source: AGHT+IH911kfyDxpLYlOQYH4x4fq16SdOBovs4K58yiNItTvK+Dxvtiq7/rW5gkv9ntkWvJXMjnErA==
X-Received: by 2002:a05:622a:5516:b0:43a:f42f:f0b4 with SMTP id d75a77b69052e-43fb165b7cfmr2013031cf.13.1716539328384;
        Fri, 24 May 2024 01:28:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:d90f:b0:23f:59fe:1665 with SMTP id
 586e51a60fabf-24c9d98c783ls294517fac.1.-pod-prod-09-us; Fri, 24 May 2024
 01:28:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVvyxK2EfvOX7ZuoKD1bdYSvIqFtob4Mkmxch7oz+XrUpkeFAlTSM/IwEdF+oe3m+xlpL09/JyqEX0TWNbKubJ2gwN4hVGkXngnug==
X-Received: by 2002:a05:6870:9721:b0:24c:6503:1e63 with SMTP id 586e51a60fabf-24ca11dec5bmr1639047fac.10.1716539327297;
        Fri, 24 May 2024 01:28:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1716539327; cv=none;
        d=google.com; s=arc-20160816;
        b=lZROJsSNQhBrUBbWGRGDdJ5Yp6IZsYV/seOV3+f3Ij+TZMQ1DRZP2pKbQHNTRuxs/+
         gY+GSdOy/tqSIAA/0HcT9BKB+mGuy+9Jozrn75N9mF/K91bw6avZholCXFWCFCr2c6Gq
         jmwnIWHnw85CfTR0G6LR8zS1Jqyl8nJBlnFz1RN7vuoqfJZ/kmJXphSpaxTG0iS6Jiye
         uOzFcoWpPIen4TYwW/ySEsM+txDqIg02e8a84KQUzJa01h1Xe6W3yQ7fLKaKES3kbUWf
         S7oTCvIcK9vfmSQlJIMLK8nXBzqaX1qJv0MuiAw8hPJmpguquDzA+N4Kt7ONaRv0ab9T
         CewQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=q54jWehm6D0NKJU6RXOGEDssE+ymCHStnW0K2QTOJ1I=;
        fh=yB+mO3hA0H90NZSQ2ZNkg6FoijmT6oIuHX8KVP0Ljxc=;
        b=P0nMyqVl7mHb99KOH+UWa9TBMmGN6fPBUTDdY+D68IJmIhBjEl+SSgj1fquReZoSKb
         ACVZfVvL+Az/aR/5mZGDTy2IHmRm62/0j4qXvoKPcxucTNurZFfl9vdyC5uDqyWEpyP9
         5pM04qWihjywzpthwLhSUijTFjM9LeA0Ipq4iuXJfH/wjFcFebvfPmFQiyVF5LpliCL4
         DeaUSVYkLilUY4HWk1zkARLLKRKJxRwW1/Q8hAPJKBs2t07DpqsTiwS1duutUBXidY64
         Es0lrVtK/9rmBGCyZRYjTjaAbdegzOa70uJTUlxXvQD8/CcZBu2IMDuBnBqNA15RHyPy
         qRRA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=YlY2WbWd;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::830 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x830.google.com (mail-qt1-x830.google.com. [2607:f8b0:4864:20::830])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-24ca28bc54dsi61807fac.3.2024.05.24.01.28.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 24 May 2024 01:28:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::830 as permitted sender) client-ip=2607:f8b0:4864:20::830;
Received: by mail-qt1-x830.google.com with SMTP id d75a77b69052e-43f84f53f66so17328221cf.3
        for <kasan-dev@googlegroups.com>; Fri, 24 May 2024 01:28:47 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVaK1X3VFoMY9BmpJQY4HUjGgu4lLppa7zLEM8Ed0gpvg+PpLI5bB7O9PHVrx4Tr7DR6M84Pt+gM5gSHyh2Kjc2epbznNE3xkOe/w==
X-Received: by 2002:a05:6214:4a86:b0:6ab:710a:d84a with SMTP id
 6a1803df08f44-6abc3e88e06mr16373676d6.23.1716539326544; Fri, 24 May 2024
 01:28:46 -0700 (PDT)
MIME-Version: 1.0
References: <20240523215029.4160518-1-bjohannesmeyer@gmail.com>
In-Reply-To: <20240523215029.4160518-1-bjohannesmeyer@gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 24 May 2024 10:28:05 +0200
Message-ID: <CAG_fn=XR6KVQ=DbKZW3kNXsCHgULm2J7i6GCm8CZUjpjuk-d2A@mail.gmail.com>
Subject: Re: [PATCH] x86: kmsan: Fix hook for unaligned accesses
To: Brian Johannesmeyer <bjohannesmeyer@gmail.com>
Cc: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Thomas Gleixner <tglx@linutronix.de>, 
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, 
	"H . Peter Anvin" <hpa@zytor.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=YlY2WbWd;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::830 as
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

On Thu, May 23, 2024 at 11:50=E2=80=AFPM Brian Johannesmeyer
<bjohannesmeyer@gmail.com> wrote:
>
> When called with a 'from' that is not 4-byte-aligned,
> string_memcpy_fromio() calls the movs() macro to copy the first few bytes=
,
> so that 'from' becomes 4-byte-aligned before calling rep_movs(). This
> movs() macro modifies 'to', and the subsequent line modifies 'n'.
>
> As a result, on unaligned accesses, kmsan_unpoison_memory() uses the
> updated (aligned) values of 'to' and 'n'. Hence, it does not unpoison the
> entire region.
>
> This patch saves the original values of 'to' and 'n', and passes those to
> kmsan_unpoison_memory(), so that the entire region is unpoisoned.

Nice catch! Does it fix any known bugs?

> Signed-off-by: Brian Johannesmeyer <bjohannesmeyer@gmail.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DXR6KVQ%3DDbKZW3kNXsCHgULm2J7i6GCm8CZUjpjuk-d2A%40mail.gm=
ail.com.
