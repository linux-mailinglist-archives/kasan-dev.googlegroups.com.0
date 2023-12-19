Return-Path: <kasan-dev+bncBDW2JDUY5AORB64RRCWAMGQE4NPZZ5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9AD79819223
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 22:19:57 +0100 (CET)
Received: by mail-pg1-x53e.google.com with SMTP id 41be03b00d2f7-5c6bd30ee89sf4642426a12.0
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 13:19:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703020796; cv=pass;
        d=google.com; s=arc-20160816;
        b=tyofnp8vhGk0PqI+GVk2Xf3E+Kx/wjtM7bwC9OWfwdjKB7sv6IClWYdTWMgoHzupQY
         zuBZCSPYAQDc4oZ6Sz9d3o2e31L4Df1yYKi7+fkfFoz/Wee5u9pArAO9aVYY3lFcPBJ5
         BbpgMzPNkFEg/QjSrwfP/DgKbCs34+TKeqhNlHI68Aa3iOpNkkj6JlEscFggzY+YXPnj
         UiBt6Hv2mPRIYDE5Mk9TBL8Sk3RE/xAzzK6Bqx0nvu+ADgmPvgjrIPiAXfTIWpR4dtEM
         NT8jNL64gxE4aVOvsnBC/QWasS9KmfwiGSFLo1TxENc5+ofoI8jq2Dn7oP+7m9YHDfMV
         nXCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=pHvANaFTDntYdkexq1qkSsTFy1v0zlpn6K9+h7Z+ttc=;
        fh=F6+FGML87yHqRev/l5aFDmOtQouYoX3HLtF8iNVpDI4=;
        b=hpbzBMWhuPtIf1XU24wPV3JbAxMwhX/izFVoltYBq79NI6GKpd3eFzWEqevLWhHdYz
         HnBWgyplCOLbvN1bv0feKTxcKhsoE6HvCe2s/3xGEIaia/RG6bhG2X7VNO06Me8WgGR+
         mxXspiJcgHz1/1k1kV2GnKqX0aRvbVOq5plL8CjFtp4k23RINzympPg1PMGOIAj0ya1B
         oxasSQYzIdEkI7qzbJY3j5AetkqttjzHnKAiXCYzBa3L3PP7LUvK2nXe11ejVMr/5V9P
         EpvumHaJnowIwdym2ncWx099bwmtvWg7HKwaDs+0AuDGWh5/0WTOkY5il1DJAntmK63+
         a04g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="bpRTJeB/";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703020796; x=1703625596; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=pHvANaFTDntYdkexq1qkSsTFy1v0zlpn6K9+h7Z+ttc=;
        b=TU6/FLr51G99KVvdmh7vNFYBPVr65Da0EJZ2FqIY/r+g26h7bG1paIpBECeN9BXrj+
         SnwsWMXE6Sm82X7pocOpq8lpjuSDryRXx7inoywXj1JBmHYpeko7ZXWzr19U+uqQpCtq
         3+dVktoRmML95WaMk/UVnoNJ4BsCfR2vQXd9H5Y5TYHlNwf9ls9RF+P8dIA/PClYDLz8
         g3du+NqCUNKP9e8xtG2X/jy6Qbzoht3JtouRFEnflcSkOzRr1Ut7NQJGcDSe+lNcq3yE
         lsM4PjP8vaVYrAClBuRZ+i3d01mwi0DAwq3wRrlu3X0LUN4jKviYdbHDBgsDxjy4YSrd
         95ZA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1703020796; x=1703625596; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=pHvANaFTDntYdkexq1qkSsTFy1v0zlpn6K9+h7Z+ttc=;
        b=IdDF6iw0t1blJ2GHFEQd6G11FEhEaVs9itaetWXmkECy2hR3t64Elm3yqCbqJs2Kg7
         4EFBDsp8J6TPXM29cGadnUKrwwm7Fj+SbvhFCoC/njk8qKnkJHzzRV6x5XZYfdu4Csi+
         1SXSf8adJwEG7ZCV2WEhfpBEkkJj7UDWnHflMrf3jDd+RNHlA+QPYKShqvEJsfj1/7Le
         Nx0AUHA9s/I7mThXx8rdQrj/Q7DZIJNoaIuoZRULB66myczux/b/vGsp/VUqOTdzE1n9
         OSRgxoAx6+hj+DLnYa3hzjkLOddPtdObbO1oWItp55a96n8S+ZupQ5upHCLJwTqTHvyi
         HsDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703020796; x=1703625596;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=pHvANaFTDntYdkexq1qkSsTFy1v0zlpn6K9+h7Z+ttc=;
        b=X2wssq5r1QVrQXGEA5YuOiBmVeIJVCp/QoGGLqM9Ur590ktaWgutZ2dBH66f1NkNir
         YY99ZYAoqd9ZiViAYp9jgX/6Eg3/xZNfQQczsmoQqp0QWwhjCWT/vXIYTTe8xZwtBpvj
         Z+IcKD1ND6ASVUbR9bVfsi0x1Ybip76UmGsww6LDAEbd6Mu9KrGMFqs00RwTXE3uPQMa
         crN+IWUczhE2DU7ptSr+EflEpUciR2W/tUuM4vpSSgXzpSa3c8xMAx4SLFObjTj92S7i
         ZZEmpoQVQlVPCutRbWqgrrz7+9IUrw9kJ7vgm4/IK2zzCf2DM/i/2RkynXvI4wFQlumh
         dbTQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxqaY0PsSYAEy0j4xrEaQfqQ9ibDvFhLkJYpomLujCzP+8AJ3dM
	K0pquqWMuAsUNp9AZ+P+Efg=
X-Google-Smtp-Source: AGHT+IEb6JGqV0oVlrPjnh9eD3IXszoFGIrNkHt9xNCXf8cJI1eBt8XZ5N1UM4NWFpuNPsdUdkVjxw==
X-Received: by 2002:a17:902:e542:b0:1d3:ac23:b511 with SMTP id n2-20020a170902e54200b001d3ac23b511mr5819501plf.54.1703020795677;
        Tue, 19 Dec 2023 13:19:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:324b:b0:1c9:ad7b:45e5 with SMTP id
 ji11-20020a170903324b00b001c9ad7b45e5ls664712plb.0.-pod-prod-08-us; Tue, 19
 Dec 2023 13:19:54 -0800 (PST)
X-Received: by 2002:a17:903:1206:b0:1d2:f388:6df3 with SMTP id l6-20020a170903120600b001d2f3886df3mr20790461plh.48.1703020794616;
        Tue, 19 Dec 2023 13:19:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703020794; cv=none;
        d=google.com; s=arc-20160816;
        b=AjveeyVKJMAkMTZg8slp1xWDrz9c2wjwa443f7jm/7yqHxQWcmrJHsEIF4bntig0fD
         I9qU7tzUrSEhOHakJ/skKOlWBKvS6O0clS/6i0WgNIiiadeelgyGVGXyRh3rJnPG9Gv2
         4wY7hFEobHDlpe0yh7RXLAGB9et+wlQ3qclD/aWbjO6IgI/aK1tA7NyBwzeGsdALXBfK
         kz4lP4TbR8q6Yttnil60JnMiWyuB5NjQ7fkqHs6RtUOB8MNqvZ6V5nmBW0Q+3oMSjvKf
         3dkJbE4xgn4nAb4/IAfxZzfHn3iBw+8bwSJWhT4I9zYOlohnBJTd+nipDCJWbxd5wHFs
         FIDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=KXbTc4Gy/r09/08lo99KiIQ8BjOLq2PAuFNDugWTr8s=;
        fh=F6+FGML87yHqRev/l5aFDmOtQouYoX3HLtF8iNVpDI4=;
        b=e2Ww4mZxcd4Hl/+Mt6k42R+d1/kJNyxxr897LxZAi6pZ9cni++LhajKw8iBB37FeSS
         Ve4iw82vjKaKfzIiN5sCS28s/g7bQdogG7ACmpzjtujLHsD4gBIy6gTumvUt9ryb9gRn
         xnYIryKg5LVfdqELVLIQILqBtuKfpGhYj0fSR2C9AbRN3/vJZeZCUouqqFdeuw3pZvM3
         vEWOq2ty0Xwc9IC/+P/QVKOYCLrDycEdwHwrVoY6rW9T06QryypsKmkjLnSs6zd3msRD
         LUCxdaRRapuWYrIC+ZdTPwzd1XGLS1/nDvMAA2zD7Ogl7Lc7f4kMD92y8owLYihZcTSg
         F6vA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="bpRTJeB/";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x1033.google.com (mail-pj1-x1033.google.com. [2607:f8b0:4864:20::1033])
        by gmr-mx.google.com with ESMTPS id kv3-20020a17090328c300b001d060bb0567si373589plb.2.2023.12.19.13.19.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Dec 2023 13:19:54 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1033 as permitted sender) client-ip=2607:f8b0:4864:20::1033;
Received: by mail-pj1-x1033.google.com with SMTP id 98e67ed59e1d1-28bcc273833so247688a91.1
        for <kasan-dev@googlegroups.com>; Tue, 19 Dec 2023 13:19:54 -0800 (PST)
X-Received: by 2002:a17:90a:458c:b0:286:6cc1:780c with SMTP id
 v12-20020a17090a458c00b002866cc1780cmr13606746pjg.79.1703020794204; Tue, 19
 Dec 2023 13:19:54 -0800 (PST)
MIME-Version: 1.0
References: <cover.1702514411.git.andreyknvl@google.com> <88fc85e2a8cca03f2bfcae76100d1a3d54eac840.1702514411.git.andreyknvl@google.com>
 <CANpmjNMNhPOBHr_5iyfP9Lo_tOUiG_bpVnS-RkfrP3JccW3yqg@mail.gmail.com>
In-Reply-To: <CANpmjNMNhPOBHr_5iyfP9Lo_tOUiG_bpVnS-RkfrP3JccW3yqg@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 19 Dec 2023 22:19:43 +0100
Message-ID: <CA+fCnZfK9XZnLeVd_Qtc5UKBze_2pUVg_XPfqMiADSUx7FajqA@mail.gmail.com>
Subject: Re: [PATCH -v2 mm 2/4] kasan: handle concurrent kasan_record_aux_stack
 calls
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Andrew Morton <akpm@linux-foundation.org>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	kasan-dev@googlegroups.com, Evgenii Stepanov <eugenis@google.com>, 
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>, 
	syzbot+186b55175d8360728234@syzkaller.appspotmail.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="bpRTJeB/";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1033
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

On Thu, Dec 14, 2023 at 9:35=E2=80=AFAM Marco Elver <elver@google.com> wrot=
e:
>
> >  #if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
> > @@ -249,6 +250,7 @@ struct kasan_global {
> >  struct kasan_alloc_meta {
> >         struct kasan_track alloc_track;
> >         /* Free track is stored in kasan_free_meta. */
> > +       spinlock_t aux_lock;
>
> This needs to be raw_spinlock, because
> kasan_record_aux_stack_noalloc() can be called from non-sleepable
> contexts (otherwise lockdep will complain for RT kernels).

Right, will fix in v3. Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZfK9XZnLeVd_Qtc5UKBze_2pUVg_XPfqMiADSUx7FajqA%40mail.gmai=
l.com.
