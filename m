Return-Path: <kasan-dev+bncBCT4XGV33UIBBCUVUX7AKGQEUPJJWAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3b.google.com (mail-vk1-xa3b.google.com [IPv6:2607:f8b0:4864:20::a3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3DCBC2CDFB3
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Dec 2020 21:28:59 +0100 (CET)
Received: by mail-vk1-xa3b.google.com with SMTP id b4sf1137707vkg.10
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Dec 2020 12:28:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607027338; cv=pass;
        d=google.com; s=arc-20160816;
        b=RA73xOGGq8xePzHmsfw6Xbf2S5zpkZ5h0x9EVD4WscbzPacb4Cuc7mWKkBUM60WcCf
         Hp3BcH2y7UJP8UztnhtsGW795xMVHLXm3q07WdKAW6rl2oh7X26ojtTrKgohiW/xctOk
         SamxcgnuJKl6/gADYjnQal72qeTToT2F9zwjZ+F+6cvPZ/ldrnhkIJEBEx72gBe9B3rO
         tOMRMGWBnmLKsRT7fd+iz673vvLg3tro+qG6UjIN5h0CKNLIHne3HFZmbrd5GpPpBItO
         zz0Wq0BYHMLMbasNbz69GlqXqtZR6KzddOOevUyuS38G5BDj7F0eP9puktihtwTwa1hF
         6fSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=RxAY+b+sp6kyhYAFJ8lG/dbSInXvT7vJvlWSnBY4jKA=;
        b=xnmH1v7LlTtpRg0Sp0En0nlU1SUEgg+sQQ9yC1MBYGmh7lyeGFBzRTk+X3MFYw1PR7
         ZVSvwSe2oMq8MoO95V6OSX/nGMf5EVV6g0tf4Fqvi08ZwfK39pUr6CrSnmxBjTckC7Vt
         jaTuwxECiOnvqPgyS7fJFnF50LR1+zkEEW/7q7E32wgbUDq35tuGAz/einHNZy4tweCC
         Q4HEEIPn+zo/Vj6JSdB5hW/e7v35aXVYFBLdhjF0VgWOiBgt6KM3gwWPaUAAETup/T4e
         JvOuB/n6Yc/q6cIvBTJ0bRFfohGhC/vhl8Yj86ECHXhmHBRuLyNGDHvRQ31wyUkwmxtV
         i2IA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=n364KfYS;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RxAY+b+sp6kyhYAFJ8lG/dbSInXvT7vJvlWSnBY4jKA=;
        b=Li44Sq9tzQZ5wBtuPxEzdFFUuualJbAIB/yl5qIzlVp3HV9syWyugp+oNdRhsPhCy4
         MPDUSDmQQdlidRKSkl+6yDlM5AmENeoxEgBiVuxXNpVEgwHo9hNnGZC48IndF8Eg/v6N
         Zaf29ZsCnRbVboWWaym804LtTDZjheASurMUOG1SvJcNKpISM78oLO3JI8+Qe//KmUzy
         uaZjRo3j2ktrUf962L19CT8CmP6xStb3zg2N2M2l1rsNhG5dYjPT/RGOuXPFSDyA5jGO
         qbHsAikqp/tyVWrUmbPmzB4w6/++GC9YH2V4XhW0nT97TmeqgiDZo4idJP7JH0h6NQoq
         oHFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RxAY+b+sp6kyhYAFJ8lG/dbSInXvT7vJvlWSnBY4jKA=;
        b=Kjt8ZsCnGf8UWqbWmCjChG9kvvxggaEwt/Ig58xBQtX5P1jk5xJduBm4NS7usVFY8J
         y7WysV7KlSJN9Xm15mYy+BbemFAfpT19+EGAvOfKNZSn5C95l6JefEyfMM6og5G/11b0
         6RNt8t9vfGcz6FXvkVhuLCEveYsa05bZqlGh8GQUP8xYXSJMbGhmuI6lJDrkuTXqIJ3H
         v06F55IE2tH/44hEzv2EYp1Ed/C5mAt/Enj+SgdLx2bORHQ2olYtBO0gMQghDOtiTAYs
         eA0bGpokO0Itn3t1lla5V8sm0Q+aqsLKs+ciDDMGDbDzi5fgSGKRqWpbB3+YYNZJBHvB
         aRmQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532z1hR/zb4f5ufuuVSjtkN8c5W4bs2j//Iv9qAmpTfPgDqlcnTX
	ZAl2FPMlEZJ1SW/klCSPJfY=
X-Google-Smtp-Source: ABdhPJx+M79TP0i25EUy+IqZhH/RxSmKb7JjaTy3eyXC+UkGcxlcp+XYnPGM/r88Lnlm5iOC5Yq7Xg==
X-Received: by 2002:a67:ee0a:: with SMTP id f10mr1135024vsp.39.1607027338303;
        Thu, 03 Dec 2020 12:28:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:2645:: with SMTP id m66ls981183vsm.3.gmail; Thu, 03 Dec
 2020 12:28:57 -0800 (PST)
X-Received: by 2002:a05:6102:802:: with SMTP id g2mr1233068vsb.8.1607027337720;
        Thu, 03 Dec 2020 12:28:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607027337; cv=none;
        d=google.com; s=arc-20160816;
        b=DzRkCnqnnCLvM7eUEm0Vz1rmxkcL3YAPeY/+iTqEqFOf8+5bu19RrToYggNM0k/4aR
         im+141OKRjhGm70MY91Bf78JNc0iU6/67v6E5yFJKfHbCC7RE5rGERdWdliUbxwaaRzT
         5i5GRJ9//2IFfoUKEMAmUoQUOeKxoRoE+c4ywpT99Uhicv1xxB0zqJCTLS+/qJg/e0do
         m2ZKq0D5yyFjXOyno08UsnKXNQ16et6ot98PO4d+8oie3k6LhwzDfRToqknNh2SQvWIT
         vGi0mUxns+ZJB8vBzI8tTgu6u9hukS/8+jEHGj2bXDWYFrd1T4v4fiukN71V5InayTMD
         j+cw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:dkim-signature:date;
        bh=gr5ESrihAJk/HGdmvqJE3hcxMjEdAOTXPdqzZOLxFek=;
        b=CeDdvc3I7A0p0PExufiYqosx6kQwpxaN15i+a/IZadBawpE12jhUupswJwd802dG12
         I4BrOFCw5pne++/Tzs/ZiXegsRBqsFD6CWAgfZAuWXooNKwJLF+wBQC7kjnHqQAm6JMk
         Z0mbyX7nZn+VYF1n0wAiPcYItUI3x1gpyqa2FYPoitrsbOW99sII054CGH9eRPC4mNQ7
         XI7GbrsFYTdjIsB4jETC2mXF7sDm4QamXe5uCd79+e2uTBTxgXDhIxLl83pCwf0QfKdV
         tH947svngRkvftLKpU3j/PC7qGvuCC8eSiHuIKb3aILTLRhQw1NDmLd32zzw4nX1REcF
         dmbQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=n364KfYS;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id y127si54763vsc.0.2020.12.03.12.28.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 03 Dec 2020 12:28:57 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Date: Thu, 3 Dec 2020 12:28:54 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, Dmitry
 Vyukov <dvyukov@google.com>, Matthias Brugger <matthias.bgg@gmail.com>,
 Nicholas Tang <nicholas.tang@mediatek.com>, Miles Chen
 <miles.chen@mediatek.com>, kasan-dev <kasan-dev@googlegroups.com>, Linux
 Memory Management List <linux-mm@kvack.org>, LKML
 <linux-kernel@vger.kernel.org>, Linux ARM
 <linux-arm-kernel@lists.infradead.org>, linux-mediatek@lists.infradead.org,
 wsd_upstream <wsd_upstream@mediatek.com>
Subject: Re: [PATCH v3 1/1] kasan: fix object remain in offline per-cpu
 quarantine
Message-Id: <20201203122854.c8d5ed270ec9cfc7c17569d9@linux-foundation.org>
In-Reply-To: <CAAeHK+z+DPNysrUwfeu27h6sKdn5DDE=BL4t96KiF0mRBNPs+Q@mail.gmail.com>
References: <1606895585-17382-1-git-send-email-Kuan-Ying.Lee@mediatek.com>
	<1606895585-17382-2-git-send-email-Kuan-Ying.Lee@mediatek.com>
	<CAAeHK+z+DPNysrUwfeu27h6sKdn5DDE=BL4t96KiF0mRBNPs+Q@mail.gmail.com>
X-Mailer: Sylpheed 3.5.1 (GTK+ 2.24.31; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=n364KfYS;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Thu, 3 Dec 2020 13:46:59 +0100 Andrey Konovalov <andreyknvl@google.com> wrote:

> >  #define QLIST_INIT { NULL, NULL, 0 }
> > @@ -188,6 +190,11 @@ void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache)
> >         local_irq_save(flags);
> >
> >         q = this_cpu_ptr(&cpu_quarantine);
> > +       if (q->offline) {
> > +               qlink_free(&info->quarantine_link, cache);
> 
> Hi Kuan-Ying,
> 
> This needs to be rebased onto the mm tree: it has some KASAN patches
> that touch this code and rename the info variable to meta.

Yup.  I'm taking care of that.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201203122854.c8d5ed270ec9cfc7c17569d9%40linux-foundation.org.
