Return-Path: <kasan-dev+bncBDW2JDUY5AORB4MZU2LQMGQEMP4CUUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 277C2588330
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Aug 2022 22:45:39 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id k3-20020ac86043000000b0033cab47c483sf796001qtm.4
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Aug 2022 13:45:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1659473138; cv=pass;
        d=google.com; s=arc-20160816;
        b=swFxWGMP22eQXo/tjZrDXB7GjL2cih2DuDIxcaHiIkuvSW79A9QKh9IUI46VxzWe+O
         AERsb7hYWwt42Arz5a6GNDy97FUaAa3l/MXOiOrQr+MGgyeD0RnFGo9whiRWiT0LGIO6
         YfQ0OUnwNfzSuSWJ1TIfASTD5opcrZYReBEFA12y8ixN0OjJ6k8op6HLDYnWgkVociUU
         jOBmGRn5TIPqU6BuSd9KIe5/5m+CcWusLPwjsYZej6/wzVEOiQCc0YxGqzOb9odAbAGI
         iOrCCHJ+eXxx0Y2Gb/ZHBwb6pFzk1rchkbTlAPtOFmbXd0abBbR02wVVJm34AH+6rQlW
         W5jg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=2O/o8SedXhPVnX/uqNNk9GrRtG9DyI9X0iOshBSd8jI=;
        b=qMC6jve2DH7rf2Z1Q5txDCsftX+2FH2y81AiuADsLXALoTX6lpAx1ikOk0GOXHHlzB
         NSUrLjF4F02BFwZiT++Sf7jJqRLuKTKFzTLlLGY1BMtji2BjjP4uhyQe7Db7srlVEooQ
         cVA/I6xh5IhAUHfZY4QXlYlYK/bsmKlx1NWyutmwkQjyDFCZTHE18R6p3IJyCHRAh+PP
         3HbVKWpI7cTcxPMUFmeaaxgLATuNHxhfhnGGwD+EJk6EqFVgnziOar0Nbdzw//qioE5E
         QzkZy+xHiZ0rJZQ2+zXTy88hnp4F3iOfEE4JRnO4HimxzTtQzQa1dT0n0hWAgVZKDjNC
         zHgQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=qbPlwMtM;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::731 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2O/o8SedXhPVnX/uqNNk9GrRtG9DyI9X0iOshBSd8jI=;
        b=g/MvXMTOWl0v8b9iD5oM+aJNtw2CRcBSFgkaoJuw4JqyJy/rHOesRSPY6nfDR5TWPq
         CBtKYAvcmE/1ducMC4kgriRSq09DajECP/b+S6YZ0PoIQhiNM5fXrX1Yxpnjs21unr2w
         rNMgyho0sEh+ZEVDcdH3w+DUoo396pSsKZVTsxINBaplGykyMu7Z2P7e5HTjIyDnL458
         vYqngn6s2/omXg0W6kr372NUmJNqRU5N+/LsKU1Jg/oK2MLj2l/XsGK5xuDuOn11Itgl
         0Tdv1gr1bWJi1oI+Y9Ni4DlGzpyi/Yxoe7smBgYoog+NPQTvG62uPkwhK+sy/mq/qK+C
         6fVw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2O/o8SedXhPVnX/uqNNk9GrRtG9DyI9X0iOshBSd8jI=;
        b=Nm4VpGeMZxDYXPwkMrCIN+vp2jkY1vkYe16mwGSLzDyXParYwaMvnxRJtDduEMne4e
         M+7/QgtUfmNsXAbRvVBGAFm+I1f6okksowJ2tYxsWRIKQ66b1HnZV0yWF0/odfvGKpqJ
         +7E7Hnk5LJYS947XTX7NZ3Z2I3ODdbK9HPKdXzgcP61SencKm/oLX0zu4NomAFplqvRZ
         WmGvhaDDJJnXWMijEKTSwIxsTdvwZDboiw8ed4BcSu+2in20Gx17ulbe7DFf0xeHPB7L
         lXf/XR6rUrFSVTeVFjhhQVhFms0GZTE7wDoLCmkQkHoV4b/FKuaS7pq962FKxc0vdwjd
         ODLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2O/o8SedXhPVnX/uqNNk9GrRtG9DyI9X0iOshBSd8jI=;
        b=xNp7U8DwmbL4HlKBmC0CYadRqlZVIQyWX3xiBc5ve+7QnUqbhGLqUxRyorQDACXWae
         yyuH0I1bax18YRalNgaGuNo/b9bFLJVRDKrbXduYvFGXbiDgmThhd/sHryBW5rHkUesN
         z22DvQOCz7pwaoaOirBXkJSwr0EJNF9xwh+SbPQW0QXEkQw2eN5Y3GWEj1a7Yr0ydjj5
         2gdBJgY43fM23mKruELAhkwWM66e6hZB2r5HQ1IVzAEpAsZAmlSukiCkrhTdJQRYVxUZ
         xGEG36qqmzCnIQyuJG+WyWcL/hw/xU+c1RqKhIYi9ocMGakpMK9Tnqqj5alZFLqvkuBv
         LNxA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora/RHz8RN1tKDpJeTBYwbwZc3G4s8Dt3EPpSdlZSfPCZjAuGG1OH
	C8Kddv03fPorbrIsDEUKfQA=
X-Google-Smtp-Source: AGRyM1szdiXBHeqhMNUXOSbvDGauhjj/by0qGhwQH0U62ED0S8KobB+nR0z0CfKoxTE03Ubg9HnoTA==
X-Received: by 2002:ac8:7dd5:0:b0:31f:20b:96f2 with SMTP id c21-20020ac87dd5000000b0031f020b96f2mr19025095qte.197.1659473138016;
        Tue, 02 Aug 2022 13:45:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:8e05:0:b0:476:9dba:4d19 with SMTP id v5-20020a0c8e05000000b004769dba4d19ls3285976qvb.11.-pod-prod-gmail;
 Tue, 02 Aug 2022 13:45:37 -0700 (PDT)
X-Received: by 2002:a05:6214:d82:b0:473:b41:aabf with SMTP id e2-20020a0562140d8200b004730b41aabfmr19695177qve.115.1659473137559;
        Tue, 02 Aug 2022 13:45:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1659473137; cv=none;
        d=google.com; s=arc-20160816;
        b=oAwwyC9al/LX+twJjfiPjwifz07k8SEHhJFVjODRQNkjumKM5OQKQ9ZpTaYXeRWU7x
         mZa3JtOLdAlShQk5kUqXQWir6PdKwJi/r23VcOuH+tjf8cL+duoiIy9bNobgQOmAUYj0
         PBIAW0Aze6u9vM1LSYoUzYfwfWJYSBXFxdq7P5jSIYWoyylWUaJC/TUFScnTYSAdKlY2
         G4/18UqS0sSqXbjqWN8d3ZQptceZ1DlsX2fD/5iMoVAR31w+Ss8GTkb89R4oLWIe13uj
         bdUU5SnCskr7YSzLUUBk15Kh0OVEbOY/wSmTGK9JUSIELYbwnniTJwNwqJ8WXx1jwQ1i
         ieaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=kGCFQktL9LEp0y8IboY5IhTEHaLuC/gj8xxem3T8C/Y=;
        b=le2wxodQbGZAy8oFSDBLQYHt6tUta2AOBsLuF1vye1kYkH5HJPsVZRX2g8l2jgVoGN
         C3BxVOy0NjKTaLPeJWiUDuuz9jvWDYEkaRpKNt+me22QghOEptSZMNVlcWk6VF9eqMsX
         nEz7r4ZDUuTJKoKElTHk+itenPov/1IsN1vG+UeflArxfHQnt7ChBwwDzyoQYQvPizPb
         eXZh9yi9GL0m9Gf5GWhPRxMy0FMzNk34MC0YgJ03kDChXl+AgHTGcfZBnS9hGTVtjKUs
         ZwKsTsPI/MBPh2Rx9TOjlimAQLGKZdLRyu7Sh9sMf7f5ivns4B5Vzsb23GqqLKtTHd4G
         rrYw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=qbPlwMtM;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::731 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qk1-x731.google.com (mail-qk1-x731.google.com. [2607:f8b0:4864:20::731])
        by gmr-mx.google.com with ESMTPS id p26-20020a05620a057a00b006b679c0753fsi505818qkp.3.2022.08.02.13.45.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Aug 2022 13:45:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::731 as permitted sender) client-ip=2607:f8b0:4864:20::731;
Received: by mail-qk1-x731.google.com with SMTP id w6so1561431qkf.3
        for <kasan-dev@googlegroups.com>; Tue, 02 Aug 2022 13:45:37 -0700 (PDT)
X-Received: by 2002:a05:620a:f93:b0:6b5:c8ff:d2d8 with SMTP id
 b19-20020a05620a0f9300b006b5c8ffd2d8mr16640819qkn.386.1659473137334; Tue, 02
 Aug 2022 13:45:37 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1658189199.git.andreyknvl@google.com> <0e910197bfbcf505122f6dae2ee9b90ff8ee31f7.1658189199.git.andreyknvl@google.com>
 <CANpmjNMrwXxU0YCwvHo59RFDkoxA-MtdrRCSPoRW+KYG2ez-NQ@mail.gmail.com> <CA+fCnZcT2iXww90CfiByAvr58XHXShiER0x0J2v14hRzNNFe9w@mail.gmail.com>
In-Reply-To: <CA+fCnZcT2iXww90CfiByAvr58XHXShiER0x0J2v14hRzNNFe9w@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 2 Aug 2022 22:45:26 +0200
Message-ID: <CA+fCnZfU5AwAbei9NqtN+FstGLJYkRe7cZrYZN1wtcGbPkqVZQ@mail.gmail.com>
Subject: Re: [PATCH mm v2 30/33] kasan: implement stack ring for tag-based modes
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Florian Mayer <fmayer@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=qbPlwMtM;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::731
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Thu, Jul 21, 2022 at 10:41 PM Andrey Konovalov <andreyknvl@gmail.com> wrote:
>
> On Tue, Jul 19, 2022 at 1:41 PM Marco Elver <elver@google.com> wrote:
> >
> > > +       for (u64 i = pos - 1; i != pos - 1 - KASAN_STACK_RING_SIZE; i--) {
> > > +               if (alloc_found && free_found)
> > > +                       break;
> > > +
> > > +               entry = &stack_ring.entries[i % KASAN_STACK_RING_SIZE];
> > > +
> > > +               /* Paired with smp_store_release() in save_stack_info(). */
> > > +               ptr = (void *)smp_load_acquire(&entry->ptr);
> > > +
> > > +               if (kasan_reset_tag(ptr) != info->object ||
> > > +                   get_tag(ptr) != get_tag(info->access_addr))
> > > +                       continue;
> > > +
> > > +               pid = READ_ONCE(entry->pid);
> > > +               stack = READ_ONCE(entry->stack);
> > > +               is_free = READ_ONCE(entry->is_free);
> > > +
> > > +               /* Try detecting if the entry was changed while being read. */
> > > +               smp_mb();
> > > +               if (ptr != (void *)READ_ONCE(entry->ptr))
> > > +                       continue;
> >
> > I thought the re-validation is no longer needed because of the rwlock
> > protection?
>
> Oh, yes, forgot to remove this. Will either do in v3 if there are more
> things to fix, or will just send a small fix-up patch if the rest of
> the series looks good.
>
> > The rest looks fine now.
>
> Thank you, Marco!

Hi Marco,

I'm thinking of sending a v3.

Does your "The rest looks fine now" comment refer only to this patch
or to the whole series? If it's the former, could you PTAL at the
other patches?

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZfU5AwAbei9NqtN%2BFstGLJYkRe7cZrYZN1wtcGbPkqVZQ%40mail.gmail.com.
