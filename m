Return-Path: <kasan-dev+bncBD66N3MZ6ALRBQUNZ6YAMGQEEOGOREY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id E90E689BD16
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Apr 2024 12:28:20 +0200 (CEST)
Received: by mail-oo1-xc3a.google.com with SMTP id 006d021491bc7-5aa3c655dacsf520066eaf.0
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Apr 2024 03:28:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712572099; cv=pass;
        d=google.com; s=arc-20160816;
        b=zMzMSUC02jU8iZOOQ8YPgSsE4EcYadcUJ2spc+pjNrv6nJoA7GvvzUEEMUuzkrB2as
         5n5f2VlAWhoB2PRtsJrRYQJwQq5VtGlNsyiWcDca9dyNFeShvZBx4psIFOLeMgZuB1ZX
         73w6VOG0frmEuqNN0mE/Secnh7FSRDxMulbOfBCDGF3Z/HcFzVt8VblTArkOyM8b0bA6
         xyRxfQ6gX4ztQ1WvpHo+9XiOyilX+QqvYavFUKUK8i88Lwbz7cuYui9dKO0z9BvViS2C
         RbqWg1ybHE7UudKLI3+TdITyLJDxaf+noFNPxDsN91t4gRVsDbhi0hp15EBSNIKUOOWt
         IFDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=Hajp75JTskT+efPoRU4dumlz01QZdTDy1s+d1i27K2k=;
        fh=9jXOG7ki+58EmX/TF/8F6QiH2lAVq6OO4fzB8ZmlIvI=;
        b=fHPg484YT2c5wRx+fCtmtzVxOtKZgZcuieQVyJ32omvs/3wr09NGc5zeTyZuuq9zdH
         TIWuXQxUXJGE5uuGRFyGUH/tMEgVntgwKFg2ltKlqcuWUDFw76ONSjvDN7zu4vTsveDo
         EMzTgzJae6rARu/ZPe5tb5AYZvG9g3zZ9sQtb6ijPCeCOyx2JNglbKsyXkTXJCpakVCu
         wxRWoGvVcTzk8LmBniBLwDUcKi07ffIEoKWTS9nHLSD3usH2lvtK8Lzf8aMJIDIobVIx
         zzw07iQI30u+JTSPP28VKuSYjgo7oOVP4POExDRLJkuQDkYNb7jH2ROL4N6jyS072IoQ
         CtDw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=ZXHoeFux;
       spf=pass (google.com: domain of oleg@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712572099; x=1713176899; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Hajp75JTskT+efPoRU4dumlz01QZdTDy1s+d1i27K2k=;
        b=wCHIEyvaTbSO6xNyhOGly289Vbrg1PfyRhjHneDVh/3YpA9s3qXWQ6xkTJVy5vlAIl
         AxhnaW099qvXgObhJgr5/Lq9iBftxXgw9Scet+A8fkPAUQsEGe9o4xzwsaOuQyGkPGcf
         SsIETsJyfxsBy7dsaEIQ+pw4UIukUtPUJyU9asaxGKMhtLrQQChPrJPiKi4Jyiz00Xhg
         rlC6r4mv/eDBqZrRR7V+jCKzChvR0g0cyQfoybM4hgwn8pCMWQTrtEkKDwCDKc2oPI02
         DWOIbDJHAt5RTIm1tx150wyBdLofsc1GpYGXmN435VaU2/m/LIJFC9GZA58s71h+UuTF
         2mHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712572099; x=1713176899;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=Hajp75JTskT+efPoRU4dumlz01QZdTDy1s+d1i27K2k=;
        b=WsiDhqLLTfNtrd6Atd9AOosqPTWGwmHGNdi/+0lG9UrrByTALGZlDECTS1UAgaY8Ua
         9FOkUYoUBtnf+fpDWT3oQKPLvv5r/HqtzgLxmUF37ffGLE2w93b/3lccPJqmeOKEd/2c
         tL7tx1ycmPUR8RQnNjLaAHiu6BKfklQOiaK6M//qDCRS6EUaG9h2glMjweU0/SLXv1vO
         RZtGmXK8cOuSh1259TUKfkLsyYyap9z5AVBO/podXFNKNejCjhdWllH1kj3dnDTa2sJY
         3yNME9Hn1mSkT6/wICKFVtnsAg2BtFPfMuBKppjHCbMxBPPlDnJIOz7T8JQlPp60F6lT
         PStg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVIkzhJnPJTfSoSUyDhB6w4wQNqaiqlsNfvrOfp7Ft8xj+XEkGVKAGJ6JNwH2WcAJ6VxRttLOOxsqgLLLdNBQzxTiV6nxdIvA==
X-Gm-Message-State: AOJu0Yy7yTB9iLwb1GzGKAC/L64VkUqqqAkOIjsxpbWRb5Bqyp46EJo+
	F83p3sEz+/6S0Hkvb5UkEZUlNNYiSh0BasRSDY0OipGmwUSLl/3Q
X-Google-Smtp-Source: AGHT+IGQ15q48c2KJEF9zUfvAg2yLPbi8w/JFULhRHhaqXBZYZfoF4BkcZaXs57d9Mfz+gYF5xxNIw==
X-Received: by 2002:a05:6820:20f:b0:5aa:4a0c:d998 with SMTP id bw15-20020a056820020f00b005aa4a0cd998mr791422oob.6.1712572099076;
        Mon, 08 Apr 2024 03:28:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:58c6:0:b0:5a4:ee4f:96d0 with SMTP id f189-20020a4a58c6000000b005a4ee4f96d0ls388514oob.0.-pod-prod-09-us;
 Mon, 08 Apr 2024 03:28:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUJq2ds82SsCQ6J8TkH/EkG3evkIbDV9DVvn6HDTL1jnanZwYNve2ph8SM2yjBdWUIsaGoX3yT1piErgLLiD59VxwG5/5HL7YlgYw==
X-Received: by 2002:a9d:5f12:0:b0:6e8:2be6:6ba2 with SMTP id f18-20020a9d5f12000000b006e82be66ba2mr9616812oti.5.1712572098191;
        Mon, 08 Apr 2024 03:28:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712572098; cv=none;
        d=google.com; s=arc-20160816;
        b=Abjb/YqTjVRJLXB4ar5RvuS0SjlS/90bgUdjyQBaG5VNPtYlPBSXUP1ojBajBSPOcb
         dk0SwjqYXBIkZikCcDVdqVOOba7ej6pxb8e76nS7lsbHZfZcLDN1+w/Gn2EFHFEdDhDa
         CuCBxHLd4UhtXZphBBDNqwFDGnOvOszLt+KTD3bNjRlIcwhUWzWW4g8CoWeB3XOvDwAj
         UiItIT41AgOJ/UHnNrIYobvlu/mayHCj7wCX6LMVZU7TTZQFiKu8eUJltcUxYGTQdwuV
         fZ3wTlVgKp1EnLLmHmwtFUQqEK2nRApxdHO3HiQWLXNDFb5fSr5+fQYK1Wb6raedkh8M
         qLOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=yVwuBF0GMcngCoZS7e29Q9IFctmXTtqweEvVhF9yYKQ=;
        fh=zru9GisBudL6wscQvdg0j2VNCYgIpM0w/4ZvPY1SZGc=;
        b=NtI6w4ZRfRlKUHcapZvs3JKYcENMUtbmZSRhlDOoLNEe67J3sLGSsGVIDZVIa2x8/8
         x8Rh6ihz4KobZuidcofF0yFBupsIXoWqFkcUTokUBDVNkyJSdDbyi2mxFdEAacP6o+j+
         Jfx/flthu8rpAFbSf2TicDPtHE1p7V89c/4S6dLsVHv/biO1xtcrtizgs/UHZwHm1SkI
         x5GOcNN4W4P/ypQsmqzsXc4gE+JzgHrcj7oYdQEy4EjZ/+HFdQP5+t3I4HnapzpxYKEe
         MF4ZG3GZYzgeGFprO4Xv73FExejXd1KsCZ+J1Xj1cW31ckENfFL0diBPylKP3SB7zZ/z
         9wEQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=ZXHoeFux;
       spf=pass (google.com: domain of oleg@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id p7-20020a9d4547000000b006ea0909afdcsi220574oti.3.2024.04.08.03.28.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Apr 2024 03:28:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of oleg@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mimecast-mx02.redhat.com (mx-ext.redhat.com [66.187.233.73])
 by relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-351-cRvw7A-sN3iP_MupvctXnA-1; Mon,
 08 Apr 2024 06:28:14 -0400
X-MC-Unique: cRvw7A-sN3iP_MupvctXnA-1
Received: from smtp.corp.redhat.com (int-mx03.intmail.prod.int.rdu2.redhat.com [10.11.54.3])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mimecast-mx02.redhat.com (Postfix) with ESMTPS id 3C8FD29AC007;
	Mon,  8 Apr 2024 10:28:13 +0000 (UTC)
Received: from dhcp-27-174.brq.redhat.com (unknown [10.45.226.180])
	by smtp.corp.redhat.com (Postfix) with SMTP id 290AF10061E0;
	Mon,  8 Apr 2024 10:28:09 +0000 (UTC)
Received: by dhcp-27-174.brq.redhat.com (nbSMTP-1.00) for uid 1000
	oleg@redhat.com; Mon,  8 Apr 2024 12:26:47 +0200 (CEST)
Date: Mon, 8 Apr 2024 12:26:39 +0200
From: Oleg Nesterov <oleg@redhat.com>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, John Stultz <jstultz@google.com>,
	Marco Elver <elver@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@kernel.org>,
	"Eric W. Biederman" <ebiederm@xmission.com>,
	linux-kernel@vger.kernel.org, linux-kselftest@vger.kernel.org,
	kasan-dev@googlegroups.com, Edward Liaw <edliaw@google.com>,
	Carlos Llamas <cmllamas@google.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Subject: Re: [PATCH] selftests/timers/posix_timers: reimplement
 check_timer_distribution()
Message-ID: <20240408102639.GA25058@redhat.com>
References: <87r0fmbe65.ffs@tglx>
 <CANDhNCoGRnXLYRzQWpy2ZzsuAXeraqT4R13tHXmiUtGzZRD3gA@mail.gmail.com>
 <87o7aqb6uw.ffs@tglx>
 <CANDhNCreA6nJp4ZUhgcxNB5Zye1aySDoU99+_GDS57HAF4jZ_Q@mail.gmail.com>
 <87frw2axv0.ffs@tglx>
 <20240404145408.GD7153@redhat.com>
 <87le5t9f14.ffs@tglx>
 <20240406150950.GA3060@redhat.com>
 <20240406151057.GB3060@redhat.com>
 <CACT4Y+Ych4+pdpcTk=yWYUOJcceL5RYoE_B9djX_pwrgOcGmFA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+Ych4+pdpcTk=yWYUOJcceL5RYoE_B9djX_pwrgOcGmFA@mail.gmail.com>
User-Agent: Mutt/1.5.24 (2015-08-30)
X-Scanned-By: MIMEDefang 3.4.1 on 10.11.54.3
X-Original-Sender: oleg@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=ZXHoeFux;
       spf=pass (google.com: domain of oleg@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
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

On 04/08, Dmitry Vyukov wrote:
>
> >
> >         if (ctd_failed)
> >                 ksft_test_result_skip("No signal distribution. Assuming old kernel\n");
>
> Shouldn't the test fail here? The goal of a test is to fail when
> things don't work.

I've copied this from the previous patch from Thomas, I am fine
either way.

> I don't see any other ksft_test_result_fail() calls, and it does not
> look that the test will hang on incorrect distribution.

Yes, it should never hang.

Thanks,

Oleg.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240408102639.GA25058%40redhat.com.
