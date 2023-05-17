Return-Path: <kasan-dev+bncBC32535MUICBBT5ESKRQMGQESJCS45Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id C9E0F70630A
	for <lists+kasan-dev@lfdr.de>; Wed, 17 May 2023 10:37:36 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id d2e1a72fcca58-6439a13ba1esf547947b3a.0
        for <lists+kasan-dev@lfdr.de>; Wed, 17 May 2023 01:37:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684312655; cv=pass;
        d=google.com; s=arc-20160816;
        b=lTXB24YohFbVAAtffTVIzH049wwIjrSuiNtANATXmgaXg3rFmqjC0tug1VS4DJX+Si
         lROQSVUEgnjPeS/r8+9C8o5jRgqmdC0UJWIbWdUab/oDnAAaPXzwF5b5jSdaPJ+yQd/9
         dTJt76Du6ymv/dobk83RuASjtgHaj9r4cRPT/Uwyv8kSSfoy3XWdfhyA3hLhZsC4hHv8
         htzs8m5hrNuQNfMp2I1Da7mjP1mf7XDaWvYPuVgisTaw6Fg8YGfr7tPnkZw6L5G3MQvL
         uS+3fvq4L6ARRreAAp6SYhkyizF16m2tQhUvNXzIL+lkZXjQ9lVBCIHdjHExtrzMMWbA
         JqtQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :organization:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=EQpJh++uTw5hST312ARXO8dfJK2aAs2bNipK40OvfBk=;
        b=eJNp4WBB92fTfHSaL4vtfgxfjTIbj49eaAAiet2kixnSY+nWUnuw/FcGpRu+boO3Sl
         F/bDhB4sHSxbSZay5yk+MyPIgP5pAggU1tD2Plo7rGot9ik2+IilDh8Q8m61VGKeSCE6
         4aHEnQGnU18v6Ty73hfprY7oqsDtnTgwkdbb1dp1LRh/yg/0EEj1OCMRrV6kUU1OpDBd
         wvJe6hwUlSiTFA/eKbad07bqhQkH0HdT1edN6vtnY23rV6hcJpfwav28nChLfce7ChPR
         bcteKgX2kq+MgeqcX26rl6ZwzYX/huGXu15rL/eKespbSkO6F+qqxX7L3MXEamG0jytQ
         jUgw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=b2Y3aEMM;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684312655; x=1686904655;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:organization:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=EQpJh++uTw5hST312ARXO8dfJK2aAs2bNipK40OvfBk=;
        b=neWYlnKbDhTw7eDMPzuMeQmt6lAUWuZB3DZENXHx74wPfOUWb6TceQ2fpGYd3/UhX+
         roSdNon6hYEEn1kGwJU9M10eb5SVm74Wf44cMPweNeIlI2T8UqoD+2Sn+nSYheJK40jr
         BDLfYclE56OM++8JrgHsDc4whSTSHvzcdXEWNUBCl76WEkUFIVT3ZKv28K7NOBKw3wKh
         4216Drk2d6uiP9xi7LZzTe0eQ+/LYtqu/daXrl8XtYRcuqiLOfFad0WpeSOGWbFPMxyR
         e6hcsXkVsfKoKlReiGagIVqgypo3PJ0vLk4azQVE0mc/1GClzKlPLZa54sUD6CfVecqR
         gkyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684312655; x=1686904655;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:organization:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=EQpJh++uTw5hST312ARXO8dfJK2aAs2bNipK40OvfBk=;
        b=a6PYElQUMA5Z/DqZR1XcLeVm/OTDhSlqfyRMeLSnAGbzvNoNtbb9uUokxsrYRNh+jp
         Mrp5KGf5QCO4jqY+voOuoO+UZSNQQ5Fd0AMF5Cq5DTRVN27lpoSdAD6zzMEgk75Ughhv
         z6znUjpG5zOW0q7J7waqO2oiWMMl/on5mYTgezyoGV+MmSi6UuRuFUsqLq8bB8eQKeIN
         NZvEWxTJ6gLtGnan7BAjrK+t/WH2ZfKG/muov3dVBnKdckxDuMEzzz8e3EDw+qVetfKe
         zVX8nW+sKytCLrMzZJIwgZhC5JH10DBsx23oUm/iz16YRsaPg/D7ZQmOwTL0iM2snI3F
         zHOg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDxmUkfV0pk3fiFGjkWMIVv/rA37PEwacQyYs1dirIG1p7kuJ8NB
	DJT5c95s0Gt7Plosn6tl0U4=
X-Google-Smtp-Source: ACHHUZ4UUiOzbQYn1PxnQRZSm5zcXWqIpbjcFNOxd5WtxtP1bIydAG0ToNGMULeqERea8A1xpfsvTw==
X-Received: by 2002:a05:6a00:21c9:b0:643:a3a6:115c with SMTP id t9-20020a056a0021c900b00643a3a6115cmr26148pfj.0.1684312655237;
        Wed, 17 May 2023 01:37:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:244e:b0:1a6:78e7:cce7 with SMTP id
 l14-20020a170903244e00b001a678e7cce7ls2585415pls.1.-pod-prod-01-us; Wed, 17
 May 2023 01:37:34 -0700 (PDT)
X-Received: by 2002:a17:902:9049:b0:1ab:19db:f2b with SMTP id w9-20020a170902904900b001ab19db0f2bmr42254990plz.36.1684312654362;
        Wed, 17 May 2023 01:37:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684312654; cv=none;
        d=google.com; s=arc-20160816;
        b=mueIahNq7Wnv/Ahod2BHfxMst1dDaQYbWZCQvFNJwgl/W6k1dC9hTOYV9oSsTmWenq
         b0k00Hhqapk8xDYM01qs8AAflPOluF+iX3ak5C2syoZPXh/D9HDnE2CApljdYzE/D7jD
         gn7dNwSnYIKOEzYgjpzjckL6aevvyRfGL5ervCMzX8qLXxZaLs1AnZUe7lvwhdrt6cDP
         vluN58TcBpIkJut0Po1nApm6B4dWOQzQ1hkvHVKuyeT1UgHDUq/Ia3+2fKt1aQnTxRrH
         tuFL5HffsLZ3KMvWBbwleWqykyRzVjpHQqmr+dBOFH00r3i3Am+dhePnCQCRCBQ0UU9M
         0bXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=97ToGLKuvaj7XmcoRhe/olZuS/lpM05KUIrSj3Fc5mA=;
        b=zwo79rmlYseDxaA2iqUzUN0NYI59CG++OoHzhlN2mYFKJhxfLqyl9EKYqeAoX5aHcZ
         YY/SctD52R1T4MezmMFXDBMqBEJnecIWFcbOLILBQTar4hmV7RpPjALwB23dWyDTPmds
         VZoqc6gz7ShEc52PvCBAdpjTVUsfVuNd53DzwqNuBJjaOYWCo4kcj+oBK2FqSTkBfHdd
         DJJHPI+IX0091FRfSLHy3WHpP2t4LVuT5JEofxZLGme+M8Xf8s6sOjC/bKrQZaH/Iijm
         Npufmsr2hEryf54slmMrMF6ICC9VhWnxpr5Yi9XzjpuUMlvUh99c2JejY6QlNYIg9iuz
         eF4A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=b2Y3aEMM;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id u10-20020a170902e80a00b001ab132cdbbcsi835657plg.12.2023.05.17.01.37.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 May 2023 01:37:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f69.google.com (mail-wm1-f69.google.com
 [209.85.128.69]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-499-HcieAPOcMfiO-X3embG2wA-1; Wed, 17 May 2023 04:37:32 -0400
X-MC-Unique: HcieAPOcMfiO-X3embG2wA-1
Received: by mail-wm1-f69.google.com with SMTP id 5b1f17b1804b1-3f518f2900eso3502865e9.2
        for <kasan-dev@googlegroups.com>; Wed, 17 May 2023 01:37:31 -0700 (PDT)
X-Received: by 2002:a05:6000:548:b0:306:4162:ebbe with SMTP id b8-20020a056000054800b003064162ebbemr27840929wrf.49.1684312650868;
        Wed, 17 May 2023 01:37:30 -0700 (PDT)
X-Received: by 2002:a05:6000:548:b0:306:4162:ebbe with SMTP id b8-20020a056000054800b003064162ebbemr27840916wrf.49.1684312650566;
        Wed, 17 May 2023 01:37:30 -0700 (PDT)
Received: from ?IPV6:2003:cb:c707:3900:757e:83f8:a99d:41ae? (p200300cbc7073900757e83f8a99d41ae.dip0.t-ipconnect.de. [2003:cb:c707:3900:757e:83f8:a99d:41ae])
        by smtp.gmail.com with ESMTPSA id r14-20020adfe68e000000b00307d58b3da9sm2030355wrm.25.2023.05.17.01.37.28
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 17 May 2023 01:37:30 -0700 (PDT)
Message-ID: <12b29199-4469-d970-579a-46a60e6e8236@redhat.com>
Date: Wed, 17 May 2023 10:37:28 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.11.0
Subject: Re: [PATCH v3 2/3] mm: Call arch_swap_restore() from unuse_pte()
To: Peter Collingbourne <pcc@google.com>,
 Catalin Marinas <catalin.marinas@arm.com>
Cc: =?UTF-8?B?UXVuLXdlaSBMaW4gKOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>,
 linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, "surenb@google.com" <surenb@google.com>,
 =?UTF-8?B?Q2hpbndlbiBDaGFuZyAo5by16Yym5paHKQ==?=
 <chinwen.chang@mediatek.com>,
 "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
 =?UTF-8?B?S3Vhbi1ZaW5nIExlZSAo5p2O5Yag56mOKQ==?=
 <Kuan-Ying.Lee@mediatek.com>, =?UTF-8?B?Q2FzcGVyIExpICjmnY7kuK3mpq4p?=
 <casper.li@mediatek.com>,
 "gregkh@linuxfoundation.org" <gregkh@linuxfoundation.org>,
 vincenzo.frascino@arm.com, Alexandru Elisei <alexandru.elisei@arm.com>,
 will@kernel.org, eugenis@google.com, Steven Price <steven.price@arm.com>
References: <20230517022115.3033604-1-pcc@google.com>
 <20230517022115.3033604-3-pcc@google.com>
From: David Hildenbrand <david@redhat.com>
Organization: Red Hat
In-Reply-To: <20230517022115.3033604-3-pcc@google.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=b2Y3aEMM;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On 17.05.23 04:21, Peter Collingbourne wrote:
> We would like to move away from requiring architectures to restore
> metadata from swap in the set_pte_at() implementation, as this is not only
> error-prone but adds complexity to the arch-specific code. This requires
> us to call arch_swap_restore() before calling swap_free() whenever pages
> are restored from swap. We are currently doing so everywhere except in
> unuse_pte(); do so there as well.
> 
> Signed-off-by: Peter Collingbourne <pcc@google.com>
> Link: https://linux-review.googlesource.com/id/I68276653e612d64cde271ce1b5a99ae05d6bbc4f
> ---
>   mm/swapfile.c | 7 +++++++
>   1 file changed, 7 insertions(+)
> 
> diff --git a/mm/swapfile.c b/mm/swapfile.c
> index 274bbf797480..e9843fadecd6 100644
> --- a/mm/swapfile.c
> +++ b/mm/swapfile.c
> @@ -1794,6 +1794,13 @@ static int unuse_pte(struct vm_area_struct *vma, pmd_t *pmd,
>   		goto setpte;
>   	}
>   
> +	/*
> +	 * Some architectures may have to restore extra metadata to the page
> +	 * when reading from swap. This metadata may be indexed by swap entry
> +	 * so this must be called before swap_free().
> +	 */
> +	arch_swap_restore(entry, page_folio(page));
> +
>   	/* See do_swap_page() */
>   	BUG_ON(!PageAnon(page) && PageMappedToDisk(page));
>   	BUG_ON(PageAnon(page) && PageAnonExclusive(page));

Acked-by: David Hildenbrand <david@redhat.com>

-- 
Thanks,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/12b29199-4469-d970-579a-46a60e6e8236%40redhat.com.
