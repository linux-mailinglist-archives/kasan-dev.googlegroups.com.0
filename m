Return-Path: <kasan-dev+bncBC7OBJGL2MHBBP5U4SZQMGQEZC3G7MQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id 556B6914316
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jun 2024 09:03:29 +0200 (CEST)
Received: by mail-io1-xd37.google.com with SMTP id ca18e2360f4ac-7f12e60c050sf378916939f.1
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jun 2024 00:03:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719212608; cv=pass;
        d=google.com; s=arc-20160816;
        b=KNtW2K+S55MFd+UBGvpJr4iGBgT2kSr7+9rAbfMieBgMi0vxLPbWlwd98f7zk7Xnqp
         ZRIolji/o2KoKzgUX8VkFOE3ohwfTLr3mdHRtLOeKSVkm22kF5qRwn3uDQeP+qV+DLmR
         j4EwsQOejAB5xivL4Zn3uY6/V66DHbEKLaYKz/fJupY3IcUDbDeYOAC97RIAegcBwaIP
         maIu9eSkmHPPQRz36r/RnmZn/zaY3E0jSezzX2dGc7wYfWP4Zadmpy+cZjhQ3zYSZ10Y
         N3RzhxfQa02RilHP2L5OvPAzgoDPZ1Q2U4NQ5PGOEDpqpcG5hU+xjcPSdq5AgonoqYyX
         g1NQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=qCWEY5dCONMIMa0rV0dC9valzwYf5yx95xiTi+SH3lI=;
        fh=22xRSSm84CORPgKwGf0+gVlNyWrZt2Y9WqdcnC5FdYY=;
        b=pTvvC/DK5wH3jBNV1gnCG7OM1zI5W5fFsB0Uu8LGg/ZvZV4fUf/r3aJvpC8Z6Abn62
         DfqMGKyIFwHcJ6LoPgg349Xu/+BaH+fmMB8wMydpvDJNnpZPl+37HUwmbM77Y+agt0vV
         qTk+zk5tT23T7jPAW3oe1ISueP9UnS4+IJMM+BEBujgR80Xp1tzHfOmhsNzYHo2Ernmg
         PXery8xvWAuI1xv8KLerocCaWUjNNxh5QQ5ev2KWuZIpeRLrD/kmOdJXW6EuXDbX9oP4
         1f+vOXpRVhxq289W1ErU8kEPmBXPwZIbW1kszCu4FiobCP/nKONBj1iXLWSqQuEdykXE
         ezRQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=jrnKlUc1;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::929 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719212608; x=1719817408; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=qCWEY5dCONMIMa0rV0dC9valzwYf5yx95xiTi+SH3lI=;
        b=AZqkUgn1EGS4MKNV11pJjulCnlmJxLCghbEnZsyNh+/6UpEkvRDJsBVTZETz1FnpwW
         nuuYgayj4rfqD1h02hCpi+JLg4lNe+AJHy/LB+Fl5JMaU5cgG5VLZQUcfARYVCb3ZqGu
         4k6ZVVDxU3DB33mXNp6RwTusVWdl/Z+Q86t/oyP5rFjmZAXGm/A+nTZSV2iitzFEpGtW
         N2aIN2jeyvSo/jOGWUyu20c9e+UJ3Bj+lHXpbIgBg61U7Vkmiz30fPGKljzGhRYePjKr
         LxYR/+NFnupgXX4rlb5TbG7Sz7YzGAvaCvz6yMyjcUeZPmP8eiTbBY+K6yF+Mt+ba8Cu
         b+nA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719212608; x=1719817408;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=qCWEY5dCONMIMa0rV0dC9valzwYf5yx95xiTi+SH3lI=;
        b=fW1+X9B00Pi3wvAKH4fKUmm7wMWAcnbf625wr6hC+BBjktmyBTL7dKprvSe56h1zj+
         ngK7PtUsrTcL1LPjg1+WminBzXTJonW8GN9kwh6gvVbCrQsoV7k5lgZ/E0wQxpOo/+xB
         3gRTp3i0ZT5oxveWyZAnGCMq55+utUUYCwgVkpnKc47/THm0fAuT45YB+wttbwjb6nrc
         FQ6Jj/yPpxO3aqdQHxvL1eXplHfjabBYkaTBhiC7K5vRbZkqmSzJ9xUIAnwqhI2uquRX
         3dbrjUVhDuK+FgvSCajhrtchnlLCQ8m5GBxWG7KItu0Em3Z55t6husOcyh7p8q30xqGL
         60ug==
X-Forwarded-Encrypted: i=2; AJvYcCX/IKVTD1l38TbCUz1X4mxKe+lUqpuLVUKD6UGy2lSCMhHG14mcQPCvgU8U4oCWI1LA4fdb/DJz6kH9JVxrauYBhVrafL0Fbg==
X-Gm-Message-State: AOJu0Ywy3bk1T1qa2kv0QC6+ADYxghmDl0fc97qzSDSZW+NR1q+7yK2w
	yXFQVxlQP0+BRf6gxa+NUPDtk9UkxeEpUoJL9b/UlzMAHi62pV3A
X-Google-Smtp-Source: AGHT+IFSoKnurpq20WGLqGshMeVZUnybKMeQUDKuyGBm7q2aiYLWoz/1L+0k30k/SffcqNZBLxhwrg==
X-Received: by 2002:a05:6e02:19cb:b0:376:41c5:d61f with SMTP id e9e14a558f8ab-37641c5d79dmr10623915ab.21.1719212607636;
        Mon, 24 Jun 2024 00:03:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:2199:b0:375:cf99:f713 with SMTP id
 e9e14a558f8ab-37626921da2ls20979045ab.0.-pod-prod-00-us; Mon, 24 Jun 2024
 00:03:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXULmiiagVe0n8pwKGRyk7ol1/xkXUkF3MA0eMQClzneptRgZ5tSQDS4zSdWt2CUIeL9Zhgc35G2VheS1HVUB7InvMfvxCOW8tPxA==
X-Received: by 2002:a05:6602:6427:b0:7eb:6ad3:8e82 with SMTP id ca18e2360f4ac-7f3a02650c5mr227986339f.5.1719212606781;
        Mon, 24 Jun 2024 00:03:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719212606; cv=none;
        d=google.com; s=arc-20160816;
        b=SXI3FPCZy3BFrRpS9Cxeate3vPFuyJW//FvvX+3dh5UZeT1ffXipK9Ql48gzawdAbW
         Fju17mkTZ1oI1xqLZkXdUg2nyyOZeZOU2J3HSOm/GISvHaKvNnC+8YdI+AL1XHvjzFCE
         uds0LRvyU/TVcB15cFhck3R9e5Y4My93GbP9WJ5UtLqXvv6i1+P1hjIqNaOJ4jphOWE6
         LY+6KvFmhJ1p78c/GIb29C9w5ZUuSDUrKv9jacO/ng41ii8P8xzu4QPoIPNylX4DA2u2
         YLBY4mhhsgJ3OqfrnyhDMETVpUVplmLNZHLvROHgLO9QhioPGwTu8d43Bn0STFKTr1Wg
         SD1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Ke6A02wcwTzqEfBmxWsw7RF5epZb5Ch9DOCFjfy+RV4=;
        fh=zbHJFz6BOgMd3tBCDVy0ZtIaSLRjylwRMvrUY2F7UFI=;
        b=Mu0suFtqBX1NF3n2/XCWbr7dSgj0W/7fSyGN6gG8OA+DKfgTuaLSfFZy/EkLIeF+Sl
         TglyRpUnmL5WeAEF0DHcHSD422ywwAo7xLi3QALwCk+6O86aViw1WxU2b5jVMGUFHOO2
         Pm8O57oI1WvkvZuDAxneeUki6CAhEZoWX0vLFPTk6qZnMtj/baXRCCAizW9npYj40Vly
         lgwZEtz+57U2WYbJouYNViqKyJumWqpsiMfkS3K6v99iVPYMttgtjC+TuSDnhH8poojd
         GkylxLcl/ZrhvBfHHUC4JcnML0Rkp2qbyR7xGDpAIEbjZoXmMNQyEu9DUZlWavQcn+id
         DefQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=jrnKlUc1;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::929 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x929.google.com (mail-ua1-x929.google.com. [2607:f8b0:4864:20::929])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4b9fa2b516asi64648173.4.2024.06.24.00.03.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 24 Jun 2024 00:03:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::929 as permitted sender) client-ip=2607:f8b0:4864:20::929;
Received: by mail-ua1-x929.google.com with SMTP id a1e0cc1a2514c-80f5cd5717cso2210502241.1
        for <kasan-dev@googlegroups.com>; Mon, 24 Jun 2024 00:03:26 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXg7MmcxhIi2kz9wTfFpiDsXcgL2Pw65lRtsuuerNIxf9bHhs7ObJfwRJa7N8yRBM3TB83yQTk2332TPWFUUuckABHAlG/N1dDyxw==
X-Received: by 2002:a05:6122:2224:b0:4ef:7292:4eb4 with SMTP id
 71dfb90a1353d-4ef72924fd2mr1178515e0c.12.1719212606035; Mon, 24 Jun 2024
 00:03:26 -0700 (PDT)
MIME-Version: 1.0
References: <20240623220606.134718-2-thorsten.blum@toblux.com>
In-Reply-To: <20240623220606.134718-2-thorsten.blum@toblux.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 24 Jun 2024 09:02:47 +0200
Message-ID: <CANpmjNMHPt7UvcZBDf-rbxP=Jm4+Ews+oYeT4b2D_nxWoN9a+g@mail.gmail.com>
Subject: Re: [PATCH] kcsan: Use min() to fix Coccinelle warning
To: Thorsten Blum <thorsten.blum@toblux.com>
Cc: dvyukov@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=jrnKlUc1;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::929 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Mon, 24 Jun 2024 at 00:08, Thorsten Blum <thorsten.blum@toblux.com> wrote:
>
> Fixes the following Coccinelle/coccicheck warning reported by
> minmax.cocci:
>
>         WARNING opportunity for min()
>
> Use size_t instead of int for the result of min().
>
> Signed-off-by: Thorsten Blum <thorsten.blum@toblux.com>

Reviewed-by: Marco Elver <elver@google.com>

Thanks for polishing (but see below). Please compile-test with
CONFIG_KCSAN=y if you haven't.

> ---
>  kernel/kcsan/debugfs.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
> index 1d1d1b0e4248..11b891fe6f7a 100644
> --- a/kernel/kcsan/debugfs.c
> +++ b/kernel/kcsan/debugfs.c
> @@ -225,7 +225,7 @@ debugfs_write(struct file *file, const char __user *buf, size_t count, loff_t *o
>  {
>         char kbuf[KSYM_NAME_LEN];
>         char *arg;
> -       int read_len = count < (sizeof(kbuf) - 1) ? count : (sizeof(kbuf) - 1);
> +       size_t read_len = min(count, (sizeof(kbuf) - 1));

While we're here polishing things this could be:

const size_t read_len = min(count, sizeof(kbuf) - 1);

( +const, remove redundant () )

>         if (copy_from_user(kbuf, buf, read_len))
>                 return -EFAULT;
> --
> 2.45.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMHPt7UvcZBDf-rbxP%3DJm4%2BEws%2BoYeT4b2D_nxWoN9a%2Bg%40mail.gmail.com.
