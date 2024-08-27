Return-Path: <kasan-dev+bncBDW2JDUY5AORBBVPWS3AMGQEZ54ZZVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id C1B2B95FDE0
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Aug 2024 02:02:15 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-42ab8492cedsf44992365e9.3
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Aug 2024 17:02:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1724716935; cv=pass;
        d=google.com; s=arc-20160816;
        b=tJ0tj0i4Ga4YwSf4V7eh7ykCVXj4j+sHpfyKEI7VK0+4TL2uEUDfnaFjn46UP9tFHC
         OyyC++LoHdwjC0qNGUj2gZCTJ4OTuIb0hrm+JNsUq4874h93qe4pS2QTRSK2s/29glKy
         +I/zTBAhVzlYFzmIKIZGtDPqUyuzGtNwsvuGBnIyH3TnE5zrhelyhr/7A79Wz5vUxyVY
         eGDmpd+oohz5eywKQrUKYhv3i/Kxfc98m+d6KYk9uIMKoJJY+UxvCkfX/kiztyP17NXQ
         itwWWe/e+Ni+lp0YX+W4+vICIhIp5VwE87DQ1aFEpgHbCt1juGjNL5qG/IWNaXDT1+aK
         tBnw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=cmmMUYQgMxjesFitWYaa+LJBT2HFP9ndwA0U+q0rDtI=;
        fh=dumb+wY/L63M2Je+fbOVy96FC8yvJIXlhGw8hl6u/sY=;
        b=mWbi6UAh7VQqeJkeEA/5r6bbTKgI7lK0aggT/aPGD9fgcvN4DGxBNeRVoyziWDzUn5
         gaB/1EeeUgIlAfPxX3nd1sauV4Y0OzsibGbiN6aC4Dpy3DYrsdgoRvTiL3a1tdRdtHlf
         7XD9/Ui/C0RgjSIYuI97RQnL7eA434xca/4CvYRSlBChNyiUgXAc1/A1wl0Cp+zAPGEK
         4+/HG5sGPBtYmBaoXI7HeoKBKjQLPDjpDt99Y6pbIpyJMnjehujEQhNQEpEE8wtp95q/
         Y+NK8r4qHDD4x9RDHL6arTYsPcw5hMeRGrry17RPjYTI131zRyYSdyh+NVyQsn+rRpXh
         M3Hg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="KL/+REhP";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1724716935; x=1725321735; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=cmmMUYQgMxjesFitWYaa+LJBT2HFP9ndwA0U+q0rDtI=;
        b=jO8AfPLnuhAkelPMzgo24QlrUd083fGROPVDcuAuvF2ZpVoP7/dXyYGUswk7Lssxa4
         wpLt+RcejTiXY6HcxF4zn5LxwUhOB16t8RkPaELNZ3nCtj9gKKboG79Y6vxsrwObYwuv
         wIHD2VwuNVolIYKVyA4O6m4HQhrwyGRdH1dxKevMbhuNsSXk53e3qQOd9zkzgQMqHh9I
         561SRoxb+lctz/qPaWRgaOimY3zaZO6jwYYdviOGku8XrnZRQxfVNIy7lo6uApNNpJf0
         Sg33H7YJRsN7kt8k8jEfY58CmZveEaBtJ5F8KInW9fy7Fh9DAwSgAfNay37ck2OISDmM
         gcug==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1724716935; x=1725321735; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=cmmMUYQgMxjesFitWYaa+LJBT2HFP9ndwA0U+q0rDtI=;
        b=HcLEOeub2IpFHaEfPDk8+m9fD9H5FCD30MVyqe5oCa93+5XevbK+l3k4ixjfsBWGUe
         MXwVnbSC1hgwJIyc2kDB4p7zzJ1u0y9mZjD/KABo2T73rIJ26eKztQ8HFJwccrC8pDGe
         Ln8IUD318rq8O46nLqGhq9ZmVIPZlWby8KHp99K/aYnD+VbKnvrnsOZaelCyYtsUOjE6
         B3RfIl3iYL/c2QaDTsm0sWERW1l0MtqVD6XG09KEEZwfgDbHQTE3xTPMfny+QyfhKD7b
         96IbtdiyvKSH4xQw+VSxzYzKE0W87oOvsk4x+ZAEyp6RXxhuUg/L/rIU8qAooFfT8RPV
         RM3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1724716935; x=1725321735;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=cmmMUYQgMxjesFitWYaa+LJBT2HFP9ndwA0U+q0rDtI=;
        b=g4ht2lbiZuV6yYHtt0dCPlpOX9hLXLZqAkwQylZ2F7X7Bvpp6tUqBgTfoFO/Himez+
         OGTNYi7WJxIo8GsNFd2K4MiBnNTCcy+n+LvRRDebzydrZelTAf8QttlKauDdyhPdUvBz
         BqVm/d6akFKaDf7qpT6+7yGqsjYDZ00q9XkG9NEcLixUuJ6HRJahbiaTKm3gWaVsgaaz
         O9z2Yze5OJKNFgU9DjfC+/oWJAdKhFees+S+uNhjUYAo1gpxsaVli5FNLLs1rKo/fVux
         ffKdbjNv1EL0mSjqJ/0xAKGwI5vdm6TSdDRe/H92TK4nQRYsB/4l9pMGTK+5JDRi2Eas
         IHaQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUN/pAex6IwUqRNSl984AT/uxMRvdxJvMBemVZ82RT7AJD27r7QDG5Y8TwqfPlygbz3KJUQeg==@lfdr.de
X-Gm-Message-State: AOJu0YzSKjPPRpxS8TAwgh78b7GUr+5UEtwWU6bu6LmTpjDpWaTiMTnw
	Rhp8K8+gCzVGArWzpDLmu+C+u+yj8/mNj9+dnhQ4atsuUQYvrbG3
X-Google-Smtp-Source: AGHT+IFhGuqRbi2IZ5aAtDH7N+0aMBGEGplYxnNmU+7OdUhqsmk9drR7RqDX0Eh1Q02PNxKWUChhdw==
X-Received: by 2002:a05:600c:4e45:b0:426:554a:e0bf with SMTP id 5b1f17b1804b1-42b9add479fmr5932315e9.16.1724716934490;
        Mon, 26 Aug 2024 17:02:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1396:b0:426:6982:f5de with SMTP id
 5b1f17b1804b1-42ac3de54bbls19009335e9.1.-pod-prod-08-eu; Mon, 26 Aug 2024
 17:02:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVrAbMkX3RbpGzKRgMaMNHivntJhUfvl5tKOqO4MgATKXKhkJP8cUAi55OL0v81KG0m2G2T+ezcvLQ=@googlegroups.com
X-Received: by 2002:a05:600c:3b95:b0:426:68f2:4d7b with SMTP id 5b1f17b1804b1-42b9adaa411mr6510435e9.3.1724716932239;
        Mon, 26 Aug 2024 17:02:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1724716932; cv=none;
        d=google.com; s=arc-20240605;
        b=G6obsQabVkYPPjC0PY3Lvn+LOkNtlkiyWaBg9uhZ/LrzERlJgbn6MBi6PW574XvMje
         EGyUaiz2kd7cvGZvNRL1T95xfV3gHNasz5LRTERDMAmVx0hUPpXf7zDP0Z/yKllh3+v7
         HF+yGS/haMtgWaB6SKO/XnCjp3n89igxjwfN9NW5vvnwhVZY/VBPmTVIlMARuOmOwgZk
         FN6MYBrE/8L8mnXxY+8h7kNPMYH/nbB/eyMBVgw2RpN6uU/EggE9TOpU3/fedVsC5RJh
         zWwcBAcNmxcrJTZs0dY4+SS6D0UWV/fxbbCkbDCknoeNsrZPYdUestxrNr0Q3dou+w56
         U6pA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=3Lu2qvntF0LW0D6rPDpqRDqugVpTuyFFhTjrSXWCWNE=;
        fh=kufgvyysvWPMj4JqA6IgDVCO+B3kUH2b/wXN0H4V1dU=;
        b=Jln8Mlsc99uc2Sx0YFxi6RY+XP4Gb86QOhojCjKMbgGzdrdgVjW6oq9R134FZ78j/J
         86zw/ym3sO8fk1RLbiTI1SrLRsMk9AbLcqrf3fQfYGVqGy7wr21iCUMe5Ms61FveTTuR
         H7lM5ZhBC6TNiF1bS/FSkLnFTJvQpw+W/idsPY5FpKBeJKQn6iM7cMpyQN3iIj4o2QIi
         FScPzYGYHsWa75w3TQMEMJ7FUmBrrsl5INTrjnLkpDVKYSDl3EIBLWs0LebIPFlSBBmu
         rojrMhR0I4hvj6SF6SFjSq/t4vxXczv5e+4Jl2fQUI1dHTH08xctQy0q0uzcopeazA2O
         pvdA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="KL/+REhP";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x334.google.com (mail-wm1-x334.google.com. [2a00:1450:4864:20::334])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-42b9e7bbda7si129645e9.1.2024.08.26.17.02.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 26 Aug 2024 17:02:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::334 as permitted sender) client-ip=2a00:1450:4864:20::334;
Received: by mail-wm1-x334.google.com with SMTP id 5b1f17b1804b1-42808071810so42323805e9.1
        for <kasan-dev@googlegroups.com>; Mon, 26 Aug 2024 17:02:12 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVMSJe6lSjnipPfmbq/tBvzaG1CL7UZ1wFoqTsYU31KCjgCRavqt3m4tYqiE4KB6NCPlDRXU/6VSiU=@googlegroups.com
X-Received: by 2002:a05:600c:5250:b0:425:7884:6b29 with SMTP id
 5b1f17b1804b1-42b9adf038dmr5996955e9.19.1724716931386; Mon, 26 Aug 2024
 17:02:11 -0700 (PDT)
MIME-Version: 1.0
References: <20240729022316.92219-1-andrey.konovalov@linux.dev>
In-Reply-To: <20240729022316.92219-1-andrey.konovalov@linux.dev>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 27 Aug 2024 02:02:00 +0200
Message-ID: <CA+fCnZc7qVTmH2neiCn3T44+C-CCyxfCKNc0FP3F9Cu0oKtBRQ@mail.gmail.com>
Subject: Re: [PATCH] usb: gadget: dummy_hcd: execute hrtimer callback in
 softirq context
To: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Cc: Alan Stern <stern@rowland.harvard.edu>, Marcello Sylvester Bauer <sylv@sylv.io>, 
	Dmitry Vyukov <dvyukov@google.com>, Aleksandr Nogikh <nogikh@google.com>, Marco Elver <elver@google.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, linux-usb@vger.kernel.org, 
	linux-kernel@vger.kernel.org, 
	syzbot+2388cdaeb6b10f0c13ac@syzkaller.appspotmail.com, 
	syzbot+17ca2339e34a1d863aad@syzkaller.appspotmail.com, stable@vger.kernel.org, 
	andrey.konovalov@linux.dev
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="KL/+REhP";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::334
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Mon, Jul 29, 2024 at 4:23=E2=80=AFAM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@gmail.com>
>
> Commit a7f3813e589f ("usb: gadget: dummy_hcd: Switch to hrtimer transfer
> scheduler") switched dummy_hcd to use hrtimer and made the timer's
> callback be executed in the hardirq context.
>
> With that change, __usb_hcd_giveback_urb now gets executed in the hardirq
> context, which causes problems for KCOV and KMSAN.
>
> One problem is that KCOV now is unable to collect coverage from
> the USB code that gets executed from the dummy_hcd's timer callback,
> as KCOV cannot collect coverage in the hardirq context.
>
> Another problem is that the dummy_hcd hrtimer might get triggered in the
> middle of a softirq with KCOV remote coverage collection enabled, and tha=
t
> causes a WARNING in KCOV, as reported by syzbot. (I sent a separate patch
> to shut down this WARNING, but that doesn't fix the other two issues.)
>
> Finally, KMSAN appears to ignore tracking memory copying operations
> that happen in the hardirq context, which causes false positive
> kernel-infoleaks, as reported by syzbot.
>
> Change the hrtimer in dummy_hcd to execute the callback in the softirq
> context.
>
> Reported-by: syzbot+2388cdaeb6b10f0c13ac@syzkaller.appspotmail.com
> Closes: https://syzkaller.appspot.com/bug?extid=3D2388cdaeb6b10f0c13ac
> Reported-by: syzbot+17ca2339e34a1d863aad@syzkaller.appspotmail.com
> Closes: https://syzkaller.appspot.com/bug?extid=3D17ca2339e34a1d863aad
> Fixes: a7f3813e589f ("usb: gadget: dummy_hcd: Switch to hrtimer transfer =
scheduler")
> Cc: stable@vger.kernel.org
> Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>

Hi Greg,

Could you pick up either this or Marcello's patch
(https://lkml.org/lkml/2024/6/26/969)? In case they got lost.

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZc7qVTmH2neiCn3T44%2BC-CCyxfCKNc0FP3F9Cu0oKtBRQ%40mail.gm=
ail.com.
